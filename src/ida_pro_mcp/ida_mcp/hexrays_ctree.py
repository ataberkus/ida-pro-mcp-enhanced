"""Hex-Rays ctree queries: call-site arguments and expression patterns.

Candidate functions come from cheap xref/immediate lookups; only those are
decompiled, and scanning stops once the requested page is filled.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable

import ida_funcs
import idaapi
import idautils

from ida_pro_mcp.vnext.contracts import ErrorCode, VNextError

from . import compat
from .sync import IDAError, idasync, tool_timeout

_MAX_DECOMPILED = 500
_MAX_ERRORS = 20
_STRING_CAP = 512
_PATTERN_OPS = ("call", "cmp", "num")
_ARG_KEY = re.compile(r"arg(\d+)$")


def _hexrays():
    try:
        import ida_hexrays
    except ImportError as exc:
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Hex-Rays APIs are not installed") from exc
    if not ida_hexrays.init_hexrays_plugin():
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Hex-Rays decompiler is unavailable")
    return ida_hexrays


def _resolve(addr: str) -> int:
    from .utils import parse_address

    try:
        return parse_address(addr)
    except IDAError as exc:
        raise VNextError(ErrorCode.INVALID_OPERATION, str(exc)) from exc


def _parse_int(text: str, what: str) -> int:
    try:
        return int(text, 0)
    except ValueError as exc:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"{what} must be an integer, got {text!r}") from exc


def parse_pattern(text: str) -> dict[str, Any]:
    """Parse ``key=value`` tokens: op, callee, value, in, argN (0-based)."""
    spec: dict[str, Any] = {"args": {}}
    for token in str(text).split():
        key, sep, value = token.partition("=")
        key = key.lower()
        if not sep or not value:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"Pattern token {token!r} is not key=value")
        arg = _ARG_KEY.match(key)
        if arg:
            if value not in {"const", "!const", "str"}:
                _parse_int(value, key)
            spec["args"][int(arg.group(1))] = value
        elif key == "value":
            spec["value"] = _parse_int(value, "value")
        elif key in {"op", "callee", "in"}:
            if key != "op":
                try:
                    re.compile(value)
                except re.error as exc:
                    raise VNextError(ErrorCode.INVALID_OPERATION, f"Invalid {key} regex {value!r}: {exc}") from exc
            spec[key] = value.lower() if key == "op" else value
        else:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"Unknown pattern key {key!r}; allowed: op, callee, value, in, argN")
    op = spec.setdefault("op", "call" if "callee" in spec or spec["args"] else "")
    if op not in _PATTERN_OPS:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"Pattern op must be one of {', '.join(_PATTERN_OPS)}")
    if op == "num" and "value" not in spec:
        raise VNextError(ErrorCode.INVALID_OPERATION, "op=num requires value=")
    if op != "call" and ("callee" in spec or spec["args"]):
        raise VNextError(ErrorCode.INVALID_OPERATION, "callee=/argN= only apply to op=call")
    if not any(key in spec for key in ("callee", "value", "in")):
        raise VNextError(ErrorCode.INVALID_OPERATION, "Pattern needs callee=, value=, or in= to bound the scan")
    return spec


def _strip_casts(expr):
    hr = _hexrays()
    while expr.op == hr.cot_cast:
        expr = expr.x
    return expr


def _string_at(ea: int) -> str | None:
    import ida_bytes
    import ida_nalt

    if not ida_bytes.is_strlit(ida_bytes.get_flags(ea)):
        return None
    raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.get_str_type(ea))
    return raw.decode("utf-8", "replace")[:_STRING_CAP] if raw else None


def _pointee(expr) -> int | None:
    """Address for obj, &obj, or &obj.field expressions."""
    hr = _hexrays()
    expr = _strip_casts(expr)
    if expr.op == hr.cot_obj:
        return int(expr.obj_ea)
    if expr.op == hr.cot_ref:
        inner = _strip_casts(expr.x)
        if inner.op == hr.cot_obj:
            return int(inner.obj_ea)
        if inner.op == hr.cot_memref and _strip_casts(inner.x).op == hr.cot_obj:
            return int(_strip_casts(inner.x).obj_ea) + int(inner.m)
    return None


def _text(expr) -> str:
    import ida_lines

    return ida_lines.tag_remove(expr.print1(None))


def _arg_row(expr) -> dict[str, Any]:
    hr = _hexrays()
    row: dict[str, Any] = {"text": _text(expr)}
    bare = _strip_casts(expr)
    if bare.op == hr.cot_num:
        row["value"] = hex(int(bare.numval()))
        return row
    if bare.op == hr.cot_str:
        row["string"] = str(bare.string)[:_STRING_CAP]
        return row
    ea = _pointee(bare)
    if ea is not None:
        row["addr"] = hex(ea)
        string = _string_at(ea)
        if string is not None:
            row["string"] = string
    return row


def _is_const(expr) -> bool:
    return _strip_casts(expr).op == _hexrays().cot_num


def _num_matches(expr, value: int) -> bool:
    """Match a cot_num against value, tolerating sign-extension to the operand width."""
    expr = _strip_casts(expr)
    if expr.op != _hexrays().cot_num:
        return False
    got = int(expr.numval())
    if got == value & 0xFFFFFFFFFFFFFFFF:
        return True
    size = expr.type.get_size()
    if size in (1, 2, 4):
        mask = (1 << (8 * size)) - 1
        return got & mask == value & mask
    return False


def _callee(call) -> tuple[int | None, str]:
    from .utils import display_name

    hr = _hexrays()
    target = _strip_casts(call.x)
    if target.op == hr.cot_obj:
        ea = int(target.obj_ea)
        return ea, display_name(ea)
    if target.op == hr.cot_helper:
        return None, str(target.helper)
    return None, _text(target)


def _call_row(call) -> dict[str, Any]:
    ea, name = _callee(call)
    row: dict[str, Any] = {"callee": name, "args": [_arg_row(arg) for arg in call.a]}
    if ea is not None:
        row["callee_addr"] = hex(ea)
    return row


def _arg_matches(expr, predicate: str) -> bool:
    if predicate == "const":
        return _is_const(expr)
    if predicate == "!const":
        return not _is_const(expr)
    if predicate == "str":
        row = _arg_row(expr)
        return "string" in row
    return _num_matches(expr, int(predicate, 0))


def _pattern_matcher(spec: dict[str, Any]) -> Callable[[Any], dict[str, Any] | None]:
    hr = _hexrays()
    comparisons = {
        hr.cot_eq: "==", hr.cot_ne: "!=",
        hr.cot_sge: ">=", hr.cot_uge: ">=", hr.cot_sle: "<=", hr.cot_ule: "<=",
        hr.cot_sgt: ">", hr.cot_ugt: ">", hr.cot_slt: "<", hr.cot_ult: "<",
    }
    op = spec["op"]
    callee_re = re.compile(spec["callee"], re.IGNORECASE) if "callee" in spec else None
    value = spec.get("value")

    def match(expr) -> dict[str, Any] | None:
        if op == "call":
            if expr.op != hr.cot_call:
                return None
            if callee_re is not None and not callee_re.search(_callee(expr)[1]):
                return None
            for index, predicate in spec["args"].items():
                if index >= len(expr.a) or not _arg_matches(expr.a[index], predicate):
                    return None
            return _call_row(expr)
        if op == "cmp":
            if expr.op not in comparisons:
                return None
            if value is not None and not (_num_matches(expr.x, value) or _num_matches(expr.y, value)):
                return None
            return {"cmp": comparisons[expr.op]}
        if expr.op == hr.cot_num and _num_matches(expr, value):
            return {}
        return None

    return match


def _scan(
    func_eas: Iterable[int],
    match: Callable[[Any], dict[str, Any] | None],
    offset: int,
    limit: int,
) -> dict[str, Any]:
    """Decompile candidates in order, collecting matches until the page plus one is filled."""
    from .utils import DecompilationError, decompile_checked, display_name

    hr = _hexrays()
    wanted = offset + limit + 1
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    scanned = 0
    exhausted = True
    candidates = sorted(set(func_eas))
    for func_ea in candidates:
        if len(rows) >= wanted:
            break
        if scanned >= _MAX_DECOMPILED:
            exhausted = False
            break
        scanned += 1
        try:
            cfunc = decompile_checked(func_ea)
        except DecompilationError as exc:
            if len(errors) < _MAX_ERRORS:
                errors.append({"func": hex(func_ea), "error": str(exc)})
            continue
        func_name = display_name(func_ea)
        found: list[dict[str, Any]] = []

        class Visitor(hr.ctree_visitor_t):
            def __init__(self):
                super().__init__(hr.CV_FAST)

            def visit_expr(self, expr):
                hit = match(expr)
                if hit is not None:
                    addr = int(expr.ea)
                    found.append(
                        {
                            "func": hex(func_ea),
                            "func_name": func_name,
                            "addr": None if addr == idaapi.BADADDR else hex(addr),
                            "text": _text(expr),
                            **hit,
                        }
                    )
                return 0

        Visitor().apply_to(cfunc.body, None)
        rows.extend(found)
    page = rows[offset : offset + limit]
    more = len(rows) > offset + limit
    return {
        "matches": page,
        "count": len(page),
        "next_offset": offset + limit if more else None,
        "candidate_functions": len(candidates),
        "scanned_functions": scanned,
        "scan_capped": not exhausted and not more,
        "errors": errors,
    }


def _callers_of(eas: set[int]) -> set[int]:
    callers: set[int] = set()
    for ea in eas:
        for xref in idautils.XrefsTo(ea):
            func = compat.get_func(xref.frm)
            if func is not None and not func.flags & ida_funcs.FUNC_THUNK:
                callers.add(int(func.start_ea))
    return callers


def with_thunks(ea: int) -> set[int]:
    """The target plus thunks one hop either way (ELF .plt stubs, j_ wrappers)."""
    targets = {ea}
    func = compat.get_func(ea)
    if func is not None and func.start_ea == ea and func.flags & ida_funcs.FUNC_THUNK:
        real, _ = ida_funcs.calc_thunk_func_target(func)
        if real != idaapi.BADADDR:
            targets.add(int(real))
    for xref in idautils.XrefsTo(ea):
        thunk = compat.get_func(xref.frm)
        if thunk is not None and thunk.flags & ida_funcs.FUNC_THUNK:
            targets.add(int(thunk.start_ea))
    return targets


@idasync
@tool_timeout(120.0)
def callsite_args(target: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
    """Every decompiled call to target with per-argument value/string/address."""
    from .utils import display_name

    _hexrays()
    ea = _resolve(target)
    func = compat.get_func(ea)
    if func is not None:
        ea = int(func.start_ea)
    targets = with_thunks(ea)

    def match(expr) -> dict[str, Any] | None:
        if expr.op != _hexrays().cot_call or _callee(expr)[0] not in targets:
            return None
        return _call_row(expr)

    result = _scan(_callers_of(targets), match, max(0, offset), max(1, limit))
    return {"query": target, "addr": hex(ea), "name": display_name(ea), **result}


def _type_names(tif) -> set[str]:
    names: set[str] = set()
    for getter in ("get_type_name", "get_final_type_name"):
        try:
            name = getattr(tif, getter)()
        except Exception:
            name = None
        if name:
            names.add(str(name))
    return names


def field_accesses(struct_name: str, byte_offset: int, member_tid: int, limit: int) -> dict[str, Any]:
    """Decompiled `s.f` / `p->f` accesses to one struct member (caller holds the IDA main thread).

    Candidates: functions with IDA member xrefs, functions whose prototype names
    the struct, and functions referencing globals typed with it.
    """
    import ida_bytes
    import ida_nalt
    import ida_typeinf

    hr = _hexrays()
    mentions = re.compile(rf"(?<![\w:]){re.escape(struct_name)}(?!\w)")
    candidates: set[int] = set()

    def add_func_of(ea: int) -> None:
        func = compat.get_func(ea)
        if func is not None:
            candidates.add(int(func.start_ea))

    if member_tid != idaapi.BADADDR:
        for xref in idautils.XrefsTo(member_tid):
            add_func_of(xref.frm)
    tif = ida_typeinf.tinfo_t()
    for ea in idautils.Functions():
        if ida_nalt.get_tinfo(tif, ea) and mentions.search(str(tif)):
            candidates.add(int(ea))
    for ea, _name in idautils.Names():
        if ida_bytes.is_code(ida_bytes.get_flags(ea)):
            continue
        if ida_nalt.get_tinfo(tif, ea) and mentions.search(str(tif)):
            for xref in idautils.XrefsTo(ea):
                add_func_of(xref.frm)

    def match(expr) -> dict[str, Any] | None:
        if expr.op not in (hr.cot_memptr, hr.cot_memref) or int(expr.m) != byte_offset:
            return None
        base = expr.x.type
        if expr.op == hr.cot_memptr:
            base = base.get_pointed_object()
        return {} if struct_name in _type_names(base) else None

    return _scan(candidates, match, 0, max(1, limit))


def _pattern_candidates(spec: dict[str, Any]) -> set[int]:
    if "in" in spec:
        scope = re.compile(spec["in"], re.IGNORECASE)
        return {
            int(ea)
            for ea in idautils.Functions()
            if scope.search(ida_funcs.get_func_name(ea) or "")
        }
    if "callee" in spec:
        callee = re.compile(spec["callee"], re.IGNORECASE)
        targets: set[int] = set()
        for ea, name in idautils.Names():
            if callee.search(name):
                targets |= with_thunks(int(ea))
        return _callers_of(targets)
    from .api_analysis import find

    hits = find("immediate", [spec["value"]], 10000, 0)[0].get("matches", [])
    funcs = [compat.get_func(int(addr, 16)) for addr in hits]
    return {int(f.start_ea) for f in funcs if f is not None}


@idasync
@tool_timeout(120.0)
def pattern_search(pattern: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
    """Match a parsed ctree pattern across bounded candidate functions."""
    _hexrays()
    spec = parse_pattern(pattern)
    result = _scan(_pattern_candidates(spec), _pattern_matcher(spec), max(0, offset), max(1, limit))
    return {"pattern": pattern, **result}
