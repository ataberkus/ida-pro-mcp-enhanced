from itertools import islice
import re
import traceback
from typing import Annotated, Optional
import ida_funcs
import idaapi
import idautils
import ida_typeinf
import ida_nalt
import ida_bytes
import ida_idaapi
import ida_ua
from .rpc import tool
from .sync import (
    idasync,
    tool_timeout,
    IDAError,
    get_error_log_path,
    get_sync_log_path,
    log_tool_diagnostic,
)
from .utils import (
    clamp_int,
    display_name,
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    get_prototype,
    paginate,
    pattern_filter,
    get_stack_frame_variables_internal,
    DecompilationError,
    decompile_function_detailed,
    decompile_function_safe,
    disasm_text,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    _collect_callees,
    _collect_callers,
    _segments,
    extract_function_strings,
    extract_function_constants,
    Argument,
    DisassemblyFunction,
    BasicBlock,
    StructFieldQuery,
    XrefQuery,
    InsnPattern,
    FuncProfileQuery,
    AnalyzeBatchQuery,
)
from . import compat


# ============================================================================
# Instruction Helpers
# ============================================================================

_BIN_SEARCH_FLAGS = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW


def _decode_insn_at(ea: int) -> ida_ua.insn_t | None:
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        return None
    return insn


def _operand_value(insn: ida_ua.insn_t, i: int) -> int | None:
    op = insn.ops[i]
    if op.type == ida_ua.o_void:
        return None
    if op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
        return op.addr
    return op.value


def _insn_mnem(insn: ida_ua.insn_t) -> str:
    try:
        return insn.get_canon_mnem().lower()
    except Exception:
        return ""


def _immediate_forms(value: int) -> set[int]:
    """Operand values IDA may store for *value* (imm32 operands are sign-extended to 64 bits)."""
    if not -0x8000000000000000 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Immediate out of range")
    forms = {value & 0xFFFFFFFFFFFFFFFF}
    if 0x80000000 <= value <= 0xFFFFFFFF:
        forms.add(value | 0xFFFFFFFF00000000)
    if value < 0 and value >= -0x80000000:
        forms.add(value & 0xFFFFFFFF)
    return forms


def _immediate_sites(value: int, offset: int, limit: int) -> tuple[list[int], bool]:
    """Code heads with an operand equal to *value*, any operand width (caller holds the main thread)."""
    import ida_search

    wanted = offset + limit + 1
    flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
    found: set[int] = set()
    for form in _immediate_forms(value):
        ea, hits = compat.inf_get_min_ea(), 0
        while hits < wanted:
            result = ida_search.find_imm(ea, flags, form)
            ea = result[0] if isinstance(result, tuple) else result
            if ea == idaapi.BADADDR:
                break
            if ida_bytes.is_code(ida_bytes.get_flags(ea)) and ea not in found:
                found.add(ea)
                hits += 1
    ordered = sorted(found)
    return ordered[offset : offset + limit], len(ordered) > offset + limit


def _parse_optional_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return int(s, 0)
        except Exception as e:
            raise ValueError(f"{field} must be an integer") from e
    try:
        return int(value)
    except Exception as e:
        raise ValueError(f"{field} must be an integer") from e


def _resolve_function_start(query: object) -> tuple[int | None, str | None]:
    from .utils import parse_address

    q = str(query or "").strip()
    if not q:
        return None, "Function query is required"

    try:
        ea = parse_address(q)
    except IDAError as exc:
        return None, f"Failed to resolve function: {exc}"

    func = ida_funcs.get_func(ea)
    if not func:
        return None, f"Not a function: {q}"
    return func.start_ea, None


def _limit_items(items: list, limit: int) -> tuple[list, bool]:
    if limit < 0:
        limit = 0
    if len(items) <= limit:
        return items, False
    return items[:limit], True


def _capped(name: str, count_key: str, items: list, limit: int) -> dict:
    """List section: first *limit* items, total count, truncation flag."""
    limited, truncated = _limit_items(items, limit)
    return {name: limited, count_key: len(items), f"{name}_truncated": truncated}


def _display_rows(rows: list[dict]) -> list[dict]:
    """{addr, name} rows with agent-friendly (demangled, short) names."""
    return [{"addr": row["addr"], "name": display_name(int(row["addr"], 16))} for row in rows]


def _basic_blocks(
    func: ida_funcs.func_t, limit: int, offset: int = 0
) -> tuple[list[BasicBlock], int]:
    """CFG blocks [offset, offset+limit) and the function's total block count."""
    chart = idaapi.FlowChart(func)
    blocks = [
        BasicBlock(
            start=hex(block.start_ea),
            end=hex(block.end_ea),
            size=block.end_ea - block.start_ea,
            type=block.type,
            successors=[hex(s.start_ea) for s in block.succs()],
            predecessors=[hex(p.start_ea) for p in block.preds()],
        )
        for block in islice(chart, offset, offset + limit)
    ]
    return blocks, chart.size


def _decompile_section(func: ida_funcs.func_t) -> tuple[str | None, str | None, dict | None]:
    """(code, error, error_details) for a function."""
    failure: dict = {}
    code = decompile_function_safe(func.start_ea, error_out=failure)
    if code is not None:
        return code, None, None
    error = failure.pop("message", "Decompilation failed without diagnostic details")
    return None, error, failure or None


def _xrefs_section(ea: int, limit: int = 200) -> dict:
    """Xrefs to/from *ea*, each side capped at *limit*."""
    xrefs = get_all_xrefs(ea)
    to_xrefs, to_truncated = _limit_items(xrefs["to"], limit)
    from_xrefs, from_truncated = _limit_items(xrefs["from"], limit)
    return {
        "to": to_xrefs,
        "from": from_xrefs,
        "to_truncated": to_truncated,
        "from_truncated": from_truncated,
        "to_count": len(xrefs["to"]),
        "from_count": len(xrefs["from"]),
    }


_EA_MARKER = re.compile(r"\s*/\*0x[0-9a-fA-F]+\*/$")
_FUNC_PTR_DECL = re.compile(r"\(\s*(?:__\w+\s*)?\*")
_STATEMENT_KEYWORDS = ("return", "goto", "break", "continue", "if", "while", "for", "do", "switch")


def _is_declaration(line: str) -> bool:
    if line.strip().startswith("//"):
        return True  # e.g. Hex-Rays' collapsed-declarations banner
    text = _EA_MARKER.sub("", line).split("//", 1)[0].strip()
    if not text.endswith(";") or "=" in text or text.split(" ", 1)[0].rstrip(";") in _STATEMENT_KEYWORDS:
        return False
    return "(" not in text or bool(_FUNC_PTR_DECL.search(text))


def decompile_view(code: str, include_declarations: bool) -> tuple[list[str], int, int]:
    """(lines, body_start_line, declaration_count) of rendered pseudocode.

    Hex-Rays prints locals right after the body `{`, then one blank line. Without
    include_declarations that block (and its blank line) is dropped from the view.
    body_start_line indexes the first statement line in the returned view."""
    lines = code.split("\n")
    brace = next((i for i, line in enumerate(lines) if line.strip() == "{"), None)
    if brace is None:
        return lines, 0, 0
    start = brace + 1
    end = start
    while end < len(lines) and lines[end].strip() and _is_declaration(lines[end]):
        end += 1
    count = end - start
    if not count or end >= len(lines) or lines[end].strip():
        return lines, start, 0  # no "decls + blank line" block
    if include_declarations:
        return lines, end + 1, count
    return lines[:start] + lines[end + 1 :], start, count


def decompile_excerpt(code: str, max_body_lines: int, include_declarations: bool) -> dict:
    """Header + first *max_body_lines* statement lines; next_line_offset continues via decompile()."""
    view, body_start, declarations = decompile_view(code, include_declarations)
    end = body_start + max(0, max_body_lines)
    more = end < len(view)
    return {
        "decompiled": "\n".join(view[:end]),
        "declarations": declarations,
        "decompile_truncated": more,
        "next_line_offset": end if more else None,
    }



def _profile_function(
    start_ea: int,
    include_lists: bool,
    max_items: int,
    include_prototype: bool,
) -> dict:
    func = ida_funcs.get_func(start_ea)
    if not func:
        return {"addr": hex(start_ea), "error": "Function not found"}

    out = {
        "addr": hex(func.start_ea),
        "name": ida_funcs.get_func_name(func.start_ea) or "<unnamed>",
        "size": hex(func.end_ea - func.start_ea),
        "instruction_count": sum(1 for _ in idautils.FuncItems(func.start_ea)),
        "basic_block_count": _basic_blocks(func, 0)[1],
        "has_type": ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), func.start_ea),
        "prototype": get_prototype(func) if include_prototype else None,
        "error": None,
    }
    for section in (
        _capped("callers", "caller_count", _collect_callers(func), max_items),
        _capped("callees", "callee_count", _collect_callees(func, call_only=False), max_items),
        _capped("strings", "string_ref_count", extract_function_strings(func.start_ea), max_items),
        _capped("constants", "constant_count", extract_function_constants(func.start_ea), max_items),
    ):
        if include_lists:
            out.update(section)
        else:
            out.update((k, v) for k, v in section.items() if k.endswith("_count"))
    return out


# ============================================================================
# Code Analysis & Decompilation
# ============================================================================


@tool
@idasync
@tool_timeout(90.0)
def decompile(
    addr: Annotated[str, "Function address or name to decompile"],
    line_offset: Annotated[int, "First line to return (0-based, in the selected view)"] = 0,
    line_limit: Annotated[int, "Max lines to return (default 400, max 5000)"] = 400,
    include_declarations: Annotated[
        bool, "Keep the local-variable declaration block (default true)"
    ] = True,
) -> dict:
    """WHEN: read one function as Hex-Rays pseudocode, page by page.
    RETURNS: {addr, function_addr, function_name, prototype, code, total_lines, body_start_line, declaration_count, next_line_offset|null}; on failure {addr, code:null, error, details?, fallback{tool:"disassemble", addr}?}.
    LIMITS: line_limit lines per call (max 5000); line_offset/total_lines/body_start_line index the selected view (without declarations when include_declarations=false). A trailing /*0xEA*/ marker maps a line to its instruction address. Non-function addresses and Hex-Rays failures return error + details + disassemble fallback.
    NEXT: call again with line_offset=next_line_offset (same include_declarations) until null; disassemble/graph_query for addresses from markers."""
    try:
        try:
            start = parse_address(addr)
        except IDAError as exc:
            return {"addr": addr, "code": None, "error": f"Function not found: {exc}"}
        if compat.IDA_VERSION >= (9, 2, 0):
            function_start = ida_funcs.get_func_start(start)
        else:
            function = ida_funcs.get_func(start)
            function_start = function.start_ea if function else idaapi.BADADDR
        if function_start == idaapi.BADADDR:
            details = {
                "input": addr,
                "resolved_addr": hex(start),
                "reason": "function_not_defined",
                "diagnostic_log": get_sync_log_path(),
                "error_log": get_error_log_path(),
            }
            error = f"No function is defined at {hex(start)}"
            log_tool_diagnostic(
                "decompile_failed", addr=addr, error=error, details=details
            )
            return {
                "addr": addr,
                "code": None,
                "error": error,
                "details": details,
                "fallback": {"tool": "disassemble", "addr": hex(start)},
            }

        function_name = display_name(function_start)
        try:
            code = decompile_function_detailed(function_start)
        except DecompilationError as exc:
            details = {
                **exc.details,
                "input": addr,
                "function_addr": hex(function_start),
                "function_name": function_name,
                "diagnostic_log": get_sync_log_path(),
                "error_log": get_error_log_path(),
            }
            log_tool_diagnostic(
                "decompile_failed",
                addr=addr,
                error=str(exc),
                details=details,
                traceback=traceback.format_exc(),
            )
            return {
                "addr": addr,
                "code": None,
                "error": str(exc),
                "details": details,
                "fallback": {
                    "tool": "disassemble",
                    "addr": hex(function_start),
                },
            }
        view, body_start, declarations = decompile_view(code, include_declarations)
        offset = max(0, int(line_offset))
        end = offset + clamp_int(line_limit, 400, 1, 5000)
        return {
            "addr": addr,
            "function_addr": hex(function_start),
            "function_name": function_name,
            "prototype": get_prototype(ida_funcs.get_func(function_start)),
            "code": "\n".join(view[offset:end]),
            "total_lines": len(view),
            "body_start_line": body_start,
            "declaration_count": declarations,
            "next_line_offset": end if end < len(view) else None,
        }
    except Exception as exc:
        details = {
            "input": addr,
            "reason": "unexpected_exception",
            "exception_type": type(exc).__name__,
            "exception": str(exc),
            "diagnostic_log": get_sync_log_path(),
            "error_log": get_error_log_path(),
        }
        log_tool_diagnostic(
            "decompile_failed",
            addr=addr,
            error=repr(exc),
            details=details,
            traceback=traceback.format_exc(),
        )
        return {
            "addr": addr,
            "code": None,
            "error": f"Unexpected decompilation failure: {exc}",
            "details": details,
        }


@tool
@idasync
@tool_timeout(90.0)
def disasm(
    addr: Annotated[str, "Function address or name to disassemble"],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 5000, max: 50000)"
    ] = 5000,
    offset: Annotated[int, "Skip first N instructions (default: 0)"] = 0,
    include_total: Annotated[
        bool, "Compute total instruction count (default: false)"
    ] = False,
) -> dict:
    """Prefer disassemble(addr, ...) for canonical disassembly.
    WHEN: disassemble from addr with offset/max_instructions paging and optional total count.
    RETURNS: {addr, asm{name, start_ea, lines, stack_frame?, return_type?, arguments?}, instruction_count, total_instructions?, cursor}.
    LIMITS: max_instructions max 50000; without include_total, total_instructions is None; continue via cursor.next."""

    # Enforce max limit
    if max_instructions <= 0:
        max_instructions = 5000
    elif max_instructions > 50000:
        max_instructions = 50000
    if offset < 0:
        offset = 0

    try:
        try:
            start = parse_address(addr)
        except IDAError as exc:
            return {"addr": addr, "asm": None, "error": f"Function not found: {exc}", "cursor": {"done": True}}
        func = ida_funcs.get_func(start)

        # Get segment info
        seg = compat.get_segment_info(start)
        if not seg:
            return {
                "addr": addr,
                "asm": None,
                "error": "No segment found",
                "cursor": {"done": True},
            }

        segment_name = compat.get_segment_name(start) or "UNKNOWN"

        if func:
            # Function exists: disassemble function items starting from requested address
            func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
            header_addr = start  # Use requested address, not function start
        else:
            # No function: disassemble sequentially from start address
            func_name = "<no function>"
            header_addr = start

        lines = []
        seen = 0
        total_count = 0
        more = False

        def _maybe_add(ea: int) -> bool:
            nonlocal seen, total_count, more
            if include_total:
                total_count += 1
            if seen < offset:
                seen += 1
                return True
            if len(lines) < max_instructions:
                lines.append(f"{ea:x}  {disasm_text(ea)}")
                seen += 1
                return True
            more = True
            seen += 1
            return include_total

        if func:
            for ea in idautils.FuncItems(func.start_ea):
                if ea == idaapi.BADADDR:
                    continue
                if ea < start:
                    continue
                if not _maybe_add(ea):
                    break
        else:
            ea = start
            while ea < seg.end_ea:
                if ea == idaapi.BADADDR:
                    break
                if _decode_insn_at(ea) is None:
                    break
                if not _maybe_add(ea):
                    break
                ea = ida_bytes.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break

        if include_total and not more:
            more = total_count > offset + max_instructions

        lines_str = f"{func_name} ({segment_name} @ {hex(header_addr)}):"
        if lines:
            lines_str += "\n" + "\n".join(lines)

        rettype = None
        args: Optional[list[Argument]] = None
        stack_frame = None

        if func:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
                ftd = ida_typeinf.func_type_data_t()
                if tif.get_func_details(ftd):
                    rettype = str(ftd.rettype)
                    args = [
                        Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                        for i, a in enumerate(ftd)
                    ]
            stack_frame = get_stack_frame_variables_internal(func.start_ea, False)

        out: DisassemblyFunction = {
            "name": func_name,
            "start_ea": hex(header_addr),
            "lines": lines_str,
        }
        if stack_frame:
            out["stack_frame"] = stack_frame
        if rettype:
            out["return_type"] = rettype
        if args is not None:
            out["arguments"] = args

        return {
            "addr": addr,
            "asm": out,
            "instruction_count": len(lines),
            "total_instructions": total_count if include_total else None,
            "cursor": ({"next": offset + max_instructions} if more else {"done": True}),
        }
    except Exception as e:
        return {
            "addr": addr,
            "asm": None,
            "error": str(e),
            "cursor": {"done": True},
        }


# ============================================================================
# Batch Analysis & Profiling
# ============================================================================


@tool
@idasync
@tool_timeout(120.0)
def func_profile(
    queries: Annotated[
        list[FuncProfileQuery] | FuncProfileQuery | str,
        "Function profiling query (supports name/address filters + pagination)",
    ],
) -> list[dict]:
    """Prefer analysis_run(mode="batch", ...) for canonical per-function metrics.
    WHEN: profile function sets (metrics + optional sampled callers/callees/strings/constants/prototype).
    RETURNS: [{query, data[profile{metrics, lists?}], next_offset, error}] per query.
    LIMITS: count max 1000, max_items max 1000; "*" scans all functions; sampled lists capped per query."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "query": s,
            "offset": 0,
            "count": 50,
            "sort_by": "addr",
            "descending": False,
            "include_lists": False,
            "max_items": 25,
            "include_prototype": False,
        },
    )

    results: list[dict] = []
    for query in queries:
        q = str(query.get("query", "*") or "*").strip()
        filter_pattern = str(query.get("filter", "") or "")
        offset = clamp_int(query.get("offset", 0), 0, 0, 2_000_000_000)
        count = clamp_int(query.get("count", 50), 50, 0, 1000)
        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))
        include_lists = bool(query.get("include_lists", False))
        max_items = clamp_int(query.get("max_items", 25), 25, 0, 1000)
        include_prototype = bool(query.get("include_prototype", False))

        # Resolve candidate function starts.
        candidates: list[dict] = []
        if q not in ("", "*"):
            start_ea, err = _resolve_function_start(q)
            if err is not None or start_ea is None:
                results.append(
                    {
                        "query": q,
                        "data": [],
                        "next_offset": None,
                        "error": err or "Failed to resolve function",
                    }
                )
                continue
            fn = ida_funcs.get_func(start_ea)
            if fn:
                candidates.append(
                    {
                        "start_ea": fn.start_ea,
                        "addr": hex(fn.start_ea),
                        "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                        "size_int": fn.end_ea - fn.start_ea,
                        "size": hex(fn.end_ea - fn.start_ea),
                    }
                )
        else:
            for start_ea in idautils.Functions():
                fn = ida_funcs.get_func(start_ea)
                if not fn:
                    continue
                candidates.append(
                    {
                        "start_ea": fn.start_ea,
                        "addr": hex(fn.start_ea),
                        "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                        "size_int": fn.end_ea - fn.start_ea,
                        "size": hex(fn.end_ea - fn.start_ea),
                    }
                )

        if filter_pattern:
            candidates = pattern_filter(candidates, filter_pattern, "name")

        if sort_by == "name":
            candidates.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            candidates.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            candidates.sort(key=lambda f: f["start_ea"], reverse=descending)

        page = paginate(candidates, offset, count)
        profiled: list[dict] = []
        for item in page["data"]:
            profiled.append(
                _profile_function(
                    int(item["start_ea"]),
                    include_lists=include_lists,
                    max_items=max_items,
                    include_prototype=include_prototype,
                )
            )

        results.append(
            {
                "query": q,
                "data": profiled,
                "next_offset": page["next_offset"],
                "error": None,
            }
        )

    return results


@tool
@idasync
@tool_timeout(120.0)
def analyze_batch(
    queries: Annotated[
        list[AnalyzeBatchQuery] | AnalyzeBatchQuery | str,
        "Comprehensive per-function analysis with selectable sections",
    ],
) -> list[dict]:
    """Prefer analysis_run(mode="batch", targets=..., options=...) for canonical batch analysis.
    WHEN: comprehensive per-function analysis with selectable sections (decompile/disasm/xrefs/callers/callees/strings/constants/blocks/proto).
    RETURNS: [{query, addr, name, analysis{size, <enabled sections only>}, error}] per query.
    LIMITS: per-section max_* caps apply (disasm 50000, strings/callees 5000, constants/blocks 10000); max_decompile_lines>0 keeps header + that many statement lines (include_declarations controls the locals block); missing query is an error entry."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "query": s,
            "include_decompile": True,
            "include_disasm": False,
            "include_xrefs": True,
            "include_callers": True,
            "include_callees": True,
            "include_strings": True,
            "include_constants": True,
            "include_basic_blocks": True,
            "include_proto": True,
            "max_disasm_insns": 300,
            "max_callers": 100,
            "max_callees": 100,
            "max_strings": 100,
            "max_constants": 200,
            "max_blocks": 500,
        },
    )

    results: list[dict] = []
    for query in queries:
        q = str(query.get("query", "") or query.get("addr", "") or "").strip()
        if not q:
            results.append(
                {
                    "query": q,
                    "addr": None,
                    "name": None,
                    "analysis": None,
                    "error": "Function query is required",
                }
            )
            continue

        start_ea, err = _resolve_function_start(q)
        if err is not None or start_ea is None:
            results.append(
                {
                    "query": q,
                    "addr": None,
                    "name": None,
                    "analysis": None,
                    "error": err or "Failed to resolve function",
                }
            )
            continue

        try:
            fn = ida_funcs.get_func(start_ea)
            if not fn:
                raise RuntimeError(f"Function not found: {q}")

            fn_name = display_name(fn.start_ea)
            size_int = fn.end_ea - fn.start_ea

            include_decompile = bool(query.get("include_decompile", True))
            include_disasm = bool(query.get("include_disasm", False))
            include_xrefs = bool(query.get("include_xrefs", True))
            include_callers = bool(query.get("include_callers", True))
            include_callees = bool(query.get("include_callees", True))
            include_strings = bool(query.get("include_strings", True))
            include_constants = bool(query.get("include_constants", True))
            include_basic_blocks = bool(query.get("include_basic_blocks", True))
            include_proto = bool(query.get("include_proto", True))

            max_disasm_insns = clamp_int(
                query.get("max_disasm_insns", 300), 300, 0, 50_000
            )
            max_callers = clamp_int(query.get("max_callers", 100), 100, 0, 5000)
            max_callees = clamp_int(query.get("max_callees", 100), 100, 0, 5000)
            max_strings = clamp_int(query.get("max_strings", 100), 100, 0, 5000)
            max_constants = clamp_int(
                query.get("max_constants", 200), 200, 0, 10000
            )
            max_blocks = clamp_int(query.get("max_blocks", 500), 500, 0, 10000)
            max_decompile_lines = clamp_int(query.get("max_decompile_lines", 0), 0, 0, 100_000)

            analysis: dict = {"size": hex(size_int)}

            if include_proto:
                analysis["prototype"] = get_prototype(fn)

            if include_decompile:
                code, error, error_details = _decompile_section(fn)
                if code is None:
                    analysis["decompile"] = None
                    analysis["decompile_error"] = error
                    analysis["decompile_error_details"] = error_details
                elif max_decompile_lines:
                    excerpt = decompile_excerpt(
                        code, max_decompile_lines, bool(query.get("include_declarations", False))
                    )
                    analysis["decompile"] = excerpt.pop("decompiled")
                    analysis.update(excerpt)
                else:
                    analysis["decompile"] = code

            if include_disasm:
                items = islice(idautils.FuncItems(fn.start_ea), max_disasm_insns + 1)
                lines, disasm_truncated = _limit_items(
                    [f"{ea:x}  {disasm_text(ea)}" for ea in items], max_disasm_insns
                )
                analysis["disasm"] = {
                    "lines": lines,
                    "instruction_count": len(lines),
                    "truncated": disasm_truncated,
                }

            if include_xrefs:
                analysis["xrefs"] = _xrefs_section(fn.start_ea)

            if include_callers:
                section = _capped("callers", "caller_count", _collect_callers(fn), max_callers)
                section["callers"] = _display_rows(section["callers"])
                analysis.update(section)

            if include_callees:
                section = _capped(
                    "callees", "callee_count", _collect_callees(fn, call_only=True), max_callees
                )
                section["callees"] = _display_rows(section["callees"])
                analysis.update(section)

            if include_strings:
                analysis.update(
                    _capped(
                        "strings",
                        "string_ref_count",
                        extract_function_strings(fn.start_ea),
                        max_strings,
                    )
                )

            if include_constants:
                analysis.update(
                    _capped(
                        "constants",
                        "constant_count",
                        extract_function_constants(fn.start_ea),
                        max_constants,
                    )
                )

            if include_basic_blocks:
                blocks, total_blocks = _basic_blocks(fn, max_blocks)
                analysis["basic_block_count"] = total_blocks
                analysis["basic_blocks"] = blocks
                analysis["basic_blocks_truncated"] = total_blocks > len(blocks)

            results.append(
                {
                    "query": q,
                    "addr": hex(fn.start_ea),
                    "name": fn_name,
                    "analysis": analysis,
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "query": q,
                    "addr": hex(start_ea),
                    "name": None,
                    "analysis": None,
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


def _func_ref(ea: int) -> dict | None:
    """{addr, name} of the function containing *ea*, or None."""
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    return {"addr": hex(func.start_ea), "name": display_name(func.start_ea)}


@tool
@idasync
def xref_query(
    queries: Annotated[
        list[XrefQuery] | XrefQuery | str,
        "Generic xref query with direction/type filters and pagination",
    ],
) -> list[dict]:
    """Prefer graph_query(kind="xrefs"|"xrefs_from"|"xrefs_both", ...) for canonical xref traversal.
    WHEN: typed xref listing around one address with direction/type filters and offset/count paging.
    RETURNS: [{query, resolved_addr, direction, xref_type, data[{direction, addr, from, to, type, fn?}], next_offset, total, error}].
    LIMITS: bad direction/xref_type fall back to both/any; count max 5000; rows deduplicated by (direction, from, to, type)."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "query": s,
            "direction": "both",
            "xref_type": "any",
            "offset": 0,
            "count": 200,
            "include_fn": True,
            "dedup": True,
            "sort_by": "addr",
            "descending": False,
        },
    )

    results: list[dict] = []
    for query in queries:
        q = str(query.get("query", "")).strip()
        direction = str(query.get("direction", "both") or "both").lower()
        xref_type = str(query.get("xref_type", "any") or "any").lower()
        offset = clamp_int(query.get("offset", 0), 0, 0, 2_000_000_000)
        count = clamp_int(query.get("count", 200), 200, 0, 5000)
        include_fn = bool(query.get("include_fn", True))
        dedup = bool(query.get("dedup", True))
        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))

        if direction not in {"to", "from", "both"}:
            direction = "both"
        if xref_type not in {"any", "code", "data"}:
            xref_type = "any"

        try:
            if not q:
                raise ValueError("query is required")
            target = parse_address(q)

            rows: list[dict] = []
            if direction in {"to", "both"}:
                for xr in idautils.XrefsTo(target, 0):
                    kind = "code" if xr.iscode else "data"
                    if xref_type != "any" and kind != xref_type:
                        continue
                    row = {
                        "direction": "to",
                        "addr": hex(xr.frm),
                        "from": hex(xr.frm),
                        "to": hex(target),
                        "type": kind,
                    }
                    if include_fn:
                        row["fn"] = _func_ref(xr.frm)
                    rows.append(row)

            if direction in {"from", "both"}:
                for xr in idautils.XrefsFrom(target, 0):
                    kind = "code" if xr.iscode else "data"
                    if xref_type != "any" and kind != xref_type:
                        continue
                    row = {
                        "direction": "from",
                        "addr": hex(xr.to),
                        "from": hex(target),
                        "to": hex(xr.to),
                        "type": kind,
                    }
                    if include_fn:
                        row["fn"] = _func_ref(xr.to)
                    rows.append(row)

            if dedup:
                seen = set()
                deduped = []
                for row in rows:
                    key = (row["direction"], row["from"], row["to"], row["type"])
                    if key in seen:
                        continue
                    seen.add(key)
                    deduped.append(row)
                rows = deduped

            if sort_by == "type":
                rows.sort(
                    key=lambda r: (str(r.get("type", "")), int(str(r["addr"]), 16)),
                    reverse=descending,
                )
            else:
                rows.sort(key=lambda r: int(str(r["addr"]), 16), reverse=descending)

            page = paginate(rows, offset, count)
            results.append(
                {
                    "query": q,
                    "resolved_addr": hex(target),
                    "direction": direction,
                    "xref_type": xref_type,
                    "data": page["data"],
                    "next_offset": page["next_offset"],
                    "total": len(rows),
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "query": q,
                    "resolved_addr": None,
                    "direction": direction,
                    "xref_type": xref_type,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    "error": str(e),
                }
            )

    return results


def _split_field_target(text: str) -> tuple[str, str]:
    """'Struct.field' or 'Struct::field' -> (struct, field)."""
    sep = "." if "." in text else "::"
    struct_name, found, field_name = str(text).strip().rpartition(sep)
    if not found or not struct_name or not field_name:
        raise ValueError(f"Expected 'Struct.field' or 'Struct::field', got {text!r}")
    return struct_name, field_name


def _field_xrefs(struct_name: str, field_name: str, offset: int, limit: int) -> dict:
    """IDA member xrefs plus Hex-Rays member accesses for one struct field."""
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not til or not tif.get_named_type(til, struct_name, ida_typeinf.BTF_STRUCT, True, False):
        raise ValueError(f"Struct '{struct_name}' not found")
    udm = ida_typeinf.udm_t()
    udm.name = field_name
    idx = tif.find_udm(udm, ida_typeinf.STRMEM_NAME)
    if idx == -1:
        members = []
        for i in range(tif.get_udt_nmembers()):
            member = ida_typeinf.udm_t()
            member.offset = i
            if tif.find_udm(member, ida_typeinf.STRMEM_INDEX) != -1:
                members.append(member.name)
        raise ValueError(f"Field '{field_name}' not found in '{struct_name}'; members: {', '.join(members[:20])}")
    byte_offset = int(udm.offset) // 8
    wanted = offset + limit + 1
    rows: dict[int, dict] = {}
    tid = tif.get_udm_tid(idx)
    if tid != ida_idaapi.BADADDR:
        for xref in islice(idautils.XrefsTo(tid), wanted):
            rows[xref.frm] = {"addr": hex(xref.frm), "type": "code" if xref.iscode else "data", "fn": _func_ref(xref.frm)}
    result: dict = {"struct": struct_name, "field": field_name, "offset": hex(byte_offset)}
    from .hexrays_ctree import field_accesses
    from ida_pro_mcp.vnext.contracts import VNextError

    try:
        scan = field_accesses(struct_name, byte_offset, tid, wanted)
    except VNextError as exc:
        result["warnings"] = [f"Decompiler accesses unavailable: {exc}"]
    else:
        for match in scan["matches"]:
            ea = int(match["addr"], 16) if match.get("addr") else int(match["func"], 16)
            rows[ea] = {
                "addr": hex(ea),
                "type": "decompiler",
                "fn": {"addr": match["func"], "name": match["func_name"]},
                "text": match["text"],
            }
        if scan["scan_capped"]:
            result["warnings"] = [f"Decompiler scan stopped after {scan['scanned_functions']} functions"]
    ordered = [rows[ea] for ea in sorted(rows)]
    result["xrefs"] = ordered[offset : offset + limit]
    result["next_offset"] = offset + limit if len(ordered) > offset + limit else None
    return result


@tool
@idasync
@tool_timeout(120.0)
def xrefs_to_field(
    queries: Annotated[
        list[StructFieldQuery] | StructFieldQuery | list[str] | str,
        "{struct, field[, offset]} records or 'Struct.field' / 'Struct::field' strings",
    ],
    limit: Annotated[int, "Max xrefs per query (default: 100, max: 1000)"] = 100,
) -> list[dict]:
    """Prefer graph_query(kind="field_xrefs", targets=["Struct.field"]) for canonical use.
    WHEN: find code that reads/writes one struct member across the IDB.
    RETURNS: [{struct, field, offset, xrefs[{addr, type(code|data|decompiler), fn{addr,name}, text?}], next_offset, warnings?, error?}] per query.
    LIMITS: limit max 1000; decompiler hits come from functions whose prototype, IDA member xrefs, or referenced globals use the struct (500 decompilations max)."""
    if isinstance(queries, (dict, str)):
        queries = [queries]
    limit = clamp_int(limit, 100, 1, 1000)
    results = []
    for query in queries:
        try:
            if isinstance(query, str):
                struct_name, field_name = _split_field_target(query)
                offset = 0
            else:
                struct_name, field_name = str(query.get("struct", "")), str(query.get("field", ""))
                offset = clamp_int(query.get("offset", 0), 0, 0, 2_000_000_000)
            results.append(_field_xrefs(struct_name, field_name, offset, limit))
        except Exception as e:
            target = query if isinstance(query, str) else f"{query.get('struct')}.{query.get('field')}"
            results.append({"query": target, "xrefs": [], "next_offset": None, "error": str(e)})
    return results


# ============================================================================
# Call Graph Analysis
# ============================================================================


@tool
@idasync
def callees(
    addrs: Annotated[list[str] | str, "Function addresses to get callees for"],
    limit: Annotated[int, "Max callees per function (default: 200, max: 500)"] = 200,
) -> list[dict]:
    """Prefer graph_query(kind="calls", targets=...) for canonical call-graph traversal.
    WHEN: list unique direct callees per function (call_only) with per-function cap.
    RETURNS: [{addr, callees[{addr, name?}], more, error}] per function.
    LIMITS: limit max 500; non-function addresses return error entries; one hop only (use callgraph/graph_query for depth)."""
    addrs = normalize_list_input(addrs)

    if limit <= 0 or limit > 500:
        limit = 500

    results = []

    for fn_addr in addrs:
        try:
            func = ida_funcs.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"addr": fn_addr, "callees": None, "error": "No function found"}
                )
                continue
            found = [
                {**row, "name": display_name(int(row["addr"], 16))}
                for row in _collect_callees(func, call_only=True)
            ]
            results.append(
                {"addr": fn_addr, "callees": found[:limit], "more": len(found) > limit}
            )
        except Exception as e:
            results.append({"addr": fn_addr, "callees": None, "error": str(e)})

    return results


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


@tool
@idasync
def find_bytes(
    patterns: Annotated[
        list[str] | str, "Byte patterns to search for (e.g. '48 8B ?? ??')"
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Prefer search(kind="bytes", targets=...) for unified search with opaque cursor.
    WHEN: scan the whole IDB for byte patterns ("48 8B ??") with offset/limit paging.
    RETURNS: [{pattern, matches[hex], n, cursor, error}] per pattern.
    LIMITS: limit max 10000; invalid patterns return build_err error entries; continue via cursor.next."""
    patterns = normalize_list_input(patterns)

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in patterns:
        matches = []
        skipped = 0
        more = False
        try:
            searcher, build_err = compat.make_bytes_searcher(pattern)
            if build_err is not None:
                results.append(
                    {
                        "pattern": pattern,
                        "matches": [],
                        "n": 0,
                        "cursor": {"done": True},
                        "error": build_err,
                    }
                )
                continue

            # Search with early exit
            ea = compat.inf_get_min_ea()
            max_ea = compat.inf_get_max_ea()
            while ea != idaapi.BADADDR:
                ea = searcher(ea, max_ea)
                if ea == idaapi.BADADDR:
                    break
                if skipped < offset:
                    skipped += 1
                else:
                    matches.append(hex(ea))
                    if len(matches) >= limit:
                        # Check if there's more
                        next_ea = searcher(ea + 1, max_ea)
                        more = next_ea != idaapi.BADADDR
                        break
                ea += 1
        except Exception as e:
            results.append(
                {
                    "pattern": pattern,
                    "matches": [],
                    "n": 0,
                    "cursor": {"done": True},
                    "error": str(e),
                }
            )
            continue

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "n": len(matches),
                "cursor": {"next": offset + limit} if more else {"done": True},
            }
        )
    return results


# ============================================================================
# Control Flow Analysis
# ============================================================================


@tool
@idasync
def basic_blocks(
    addrs: Annotated[list[str] | str, "Function addresses to get basic blocks for"],
    max_blocks: Annotated[
        int, "Max basic blocks per function (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N blocks (default: 0)"] = 0,
) -> list[dict]:
    """Prefer graph_query(kind="cfg", targets=...) for canonical CFG blocks.
    WHEN: list CFG blocks per function with offset/max_blocks paging.
    RETURNS: [{addr, blocks[{start, end, type?, succs, preds}], count, total_blocks, cursor, error}].
    LIMITS: max_blocks max 10000; unresolved/non-function addresses return error entries; continue via cursor.next."""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_blocks <= 0 or max_blocks > 10000:
        max_blocks = 10000

    results = []
    for fn_addr in addrs:
        try:
            ea, resolve_error = _resolve_function_start(fn_addr)
            if ea is None:
                results.append(
                    {
                        "addr": fn_addr,
                        "error": f"Function not found: {resolve_error}" if resolve_error else "Function not found",
                        "blocks": [],
                        "cursor": {"done": True},
                    }
                )
                continue
            func = ida_funcs.get_func(ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        "error": "Function not found",
                        "blocks": [],
                        "cursor": {"done": True},
                    }
                )
                continue

            blocks, total_blocks = _basic_blocks(func, max_blocks, max(0, offset))
            more = offset + max_blocks < total_blocks

            results.append(
                {
                    "addr": fn_addr,
                    "blocks": blocks,
                    "count": len(blocks),
                    "total_blocks": total_blocks,
                    "cursor": (
                        {"next": offset + max_blocks} if more else {"done": True}
                    ),
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": fn_addr,
                    "error": str(e),
                    "blocks": [],
                    "cursor": {"done": True},
                }
            )
    return results


# ============================================================================
# Search Operations
# ============================================================================


@tool
@idasync
def find(
    type: Annotated[
        str, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"
    ],
    targets: Annotated[
        list[str | int] | str | int, "Search targets (strings, integers, or addresses)"
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Prefer search(kind="constant", targets=...) for immediates; search(kind="text") for strings.
    WHEN: search by type string|immediate|data_ref|code_ref with offset/limit paging.
    RETURNS: [{query, matches[hex], count, cursor, error}] per target.
    LIMITS: limit max 10000; unknown type string returns an error entry listing Allowed values."""
    if not isinstance(targets, list):
        targets = [targets]
    # Enforce max limit to prevent token overflow
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    if type == "string":
        # Raw byte search for UTF-8 substrings across the binary
        for pattern in targets:
            pattern_str = str(pattern)
            pattern_bytes = pattern_str.encode("utf-8")
            if not pattern_bytes:
                results.append(
                    {
                        "query": pattern_str,
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": "Empty pattern",
                    }
                )
                continue

            matches = []
            skipped = 0
            more = False
            try:
                ea = compat.inf_get_min_ea()
                max_ea = compat.inf_get_max_ea()
                mask = b"\xff" * len(pattern_bytes)
                while ea != idaapi.BADADDR:
                    ea = compat.raw_bin_search(ea, max_ea, pattern_bytes, mask, _BIN_SEARCH_FLAGS)
                    if ea != idaapi.BADADDR:
                        if skipped < offset:
                            skipped += 1
                        else:
                            matches.append(hex(ea))
                            if len(matches) >= limit:
                                next_ea = compat.raw_bin_search(
                                    ea + 1, max_ea, pattern_bytes, mask, _BIN_SEARCH_FLAGS
                                )
                                more = next_ea != idaapi.BADADDR
                                break
                        ea += 1
            except Exception:
                pass

            results.append(
                {
                    "query": pattern_str,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if more else {"done": True},
                    "error": None,
                }
            )

    elif type == "immediate":
        # Search for immediate values
        for value in targets:
            if isinstance(value, str):
                try:
                    value = int(value, 0)
                except ValueError:
                    results.append(
                        {"query": value, "matches": [], "count": 0, "cursor": {"done": True}, "error": f"Invalid immediate: {value!r}"}
                    )
                    continue

            try:
                matches, more = _immediate_sites(value, offset, limit)
            except ValueError as exc:
                results.append(
                    {"query": value, "matches": [], "count": 0, "cursor": {"done": True}, "error": str(exc)}
                )
                continue
            matches = [hex(ea) for ea in matches]

            results.append(
                {
                    "query": value,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if more else {"done": True},
                    "error": None,
                }
            )

    elif type == "data_ref":
        # Find all data references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                gen = (hex(xref) for xref in idautils.DataRefsTo(target))
                # Skip offset items, take limit+1 to check more
                matches = list(islice(islice(gen, offset, None), limit + 1))
                more = len(matches) > limit
                if more:
                    matches = matches[:limit]

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    elif type == "code_ref":
        # Find all code references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                gen = (hex(xref) for xref in idautils.CodeRefsTo(target, 0))
                # Skip offset items, take limit+1 to check more
                matches = list(islice(islice(gen, offset, None), limit + 1))
                more = len(matches) > limit
                if more:
                    matches = matches[:limit]

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    else:
        allowed_find_types = ("string", "immediate", "data_ref", "code_ref")
        results.append(
            {
                "query": None,
                "matches": [],
                "count": 0,
                "cursor": {"done": True},
                "error": f"Unknown search type: {type}. Allowed: {', '.join(allowed_find_types)}",
            }
        )

    return results


def _resolve_insn_scan_ranges(
    pattern: dict, allow_broad: bool
) -> tuple[list[tuple[int, int]], str | None]:
    func_addr = pattern.get("func")
    segment_name = pattern.get("segment")
    start_s = pattern.get("start")
    end_s = pattern.get("end")

    exec_segments = _segments(exec_only=True)

    if func_addr is not None:
        try:
            ea = parse_address(func_addr)
            func = ida_funcs.get_func(ea)
            if not func:
                return [], f"Function not found at {func_addr}"
            return [(func.start_ea, func.end_ea)], None
        except Exception as e:
            return [], str(e)

    if segment_name is not None:
        for seg_start, seg_end in exec_segments:
            if compat.get_segment_name(seg_start) == segment_name:
                return [(seg_start, seg_end)], None
        return [], f"Executable segment not found: {segment_name}"

    if start_s is not None or end_s is not None:
        if start_s is None:
            return [], "start is required when end is set"
        try:
            start_ea = parse_address(start_s)
            end_ea = parse_address(end_s) if end_s is not None else None
        except Exception as e:
            return [], str(e)

        if not exec_segments:
            return [], "No executable segments found"

        if end_ea is None:
            end_ea = next((e for s, e in exec_segments if s <= start_ea < e), None)
            if end_ea is None:
                return [], "start address not in executable segment"

        if end_ea <= start_ea:
            return [], "end must be greater than start"

        ranges = []
        for seg_start, seg_end in exec_segments:
            seg_start = max(seg_start, start_ea)
            seg_end = min(seg_end, end_ea)
            if seg_end > seg_start:
                ranges.append((seg_start, seg_end))

        if not ranges:
            return [], "No executable ranges within start/end"

        return ranges, None

    if not allow_broad:
        return [], "Scope required: set func/segment/start/end or allow_broad=true"

    if not exec_segments:
        return [], "No executable segments found"

    return exec_segments, None


def _operands_match_text(ea: int, insn: ida_ua.insn_t, op_texts: dict[int | str, str]) -> bool:
    """Case-insensitive operand-text substring filters; key "any" matches any operand."""
    import idc

    texts = []
    for i in range(8):
        if insn.ops[i].type == ida_ua.o_void:
            break
        texts.append((idc.print_operand(ea, i) or "").lower())
    for key, needle in op_texts.items():
        if key == "any":
            if not any(needle in text for text in texts):
                return False
        elif key >= len(texts) or needle not in texts[key]:
            return False
    return True


def _scan_insn_ranges(
    ranges: list[tuple[int, int]],
    mnem: str,
    op0_val: int | None,
    op1_val: int | None,
    op2_val: int | None,
    any_val: int | None,
    limit: int,
    offset: int,
    max_scan_insns: int,
    op_texts: dict[int | str, str] | None = None,
) -> tuple[list[str], bool, int, bool, int | None]:
    matches: list[str] = []
    skipped = 0
    scanned = 0
    more = False
    truncated = False
    next_start: int | None = None

    for start_ea, end_ea in ranges:
        ea = start_ea
        while ea < end_ea:
            if scanned >= max_scan_insns:
                truncated = True
                next_start = ea
                break

            scanned += 1

            insn = _decode_insn_at(ea)
            if insn is None:
                ea = ida_bytes.next_head(ea, end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            if mnem and _insn_mnem(insn) != mnem:
                ea = ida_bytes.next_head(ea, end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            match = True
            if op0_val is not None and _operand_value(insn, 0) != op0_val:
                match = False
            if op1_val is not None and _operand_value(insn, 1) != op1_val:
                match = False
            if op2_val is not None and _operand_value(insn, 2) != op2_val:
                match = False

            if any_val is not None and match:
                found_any = False
                for i in range(8):
                    if insn.ops[i].type == ida_ua.o_void:
                        break
                    if _operand_value(insn, i) == any_val:
                        found_any = True
                        break
                if not found_any:
                    match = False

            if op_texts and match:
                match = _operands_match_text(ea, insn, op_texts)

            if match:
                if skipped < offset:
                    skipped += 1
                else:
                    matches.append(hex(ea))
                    if len(matches) > limit:
                        more = True
                        matches = matches[:limit]
                        break

            ea = ida_bytes.next_head(ea, end_ea)
            if ea == idaapi.BADADDR:
                break

        if more or truncated:
            break

    return matches, more, scanned, truncated, next_start


@tool
@idasync
def insn_query(
    queries: Annotated[
        list[InsnPattern] | InsnPattern | str,
        "Instruction query with mnemonic/operand filters and scoped scan",
    ],
) -> list[dict]:
    """Prefer search(kind="instruction", targets=[mnem], ...) for unified instruction search.
    WHEN: mnemonic/operand-filtered scan scoped by func/segment/start/end with offset/count paging.
    RETURNS: [{query, ranges[{start, end}], matches[{addr, disasm?, fn?}], count, cursor, scanned, truncated, next_start, error}].
    LIMITS: count max 5000, max_scan_insns max 2000000; unscoped scans need allow_broad or they error."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "mnem": s,
            "offset": 0,
            "count": 100,
            "max_scan_insns": 200000,
            "allow_broad": False,
            "include_fn": False,
            "include_disasm": False,
        },
    )

    results: list[dict] = []
    for pattern in queries:
        mnem = str(pattern.get("mnem", "") or "").strip().lower()
        if mnem == "*":
            mnem = ""

        offset = clamp_int(pattern.get("offset", 0), 0, 0, 2_000_000_000)
        count = clamp_int(pattern.get("count", 100), 100, 0, 5000)
        max_scan_insns = clamp_int(
            pattern.get("max_scan_insns", 200000), 200000, 1, 2_000_000
        )
        allow_broad = bool(pattern.get("allow_broad", False))
        include_fn = bool(pattern.get("include_fn", False))
        include_disasm = bool(pattern.get("include_disasm", False))

        summary = {
            "mnem": mnem or None,
            "op0": pattern.get("op0"),
            "op1": pattern.get("op1"),
            "op2": pattern.get("op2"),
            "op_any": pattern.get("op_any"),
            "func": pattern.get("func"),
            "segment": pattern.get("segment"),
            "start": pattern.get("start"),
            "end": pattern.get("end"),
            "offset": offset,
            "count": count,
            "max_scan_insns": max_scan_insns,
            "allow_broad": allow_broad,
        }

        try:
            op0_val = _parse_optional_int(pattern.get("op0"), "op0")
            op1_val = _parse_optional_int(pattern.get("op1"), "op1")
            op2_val = _parse_optional_int(pattern.get("op2"), "op2")
            any_val = _parse_optional_int(pattern.get("op_any"), "op_any")

            ranges, range_error = _resolve_insn_scan_ranges(pattern, allow_broad)
            if range_error:
                raise ValueError(range_error)

            addresses, more, scanned, truncated, next_start = _scan_insn_ranges(
                ranges,
                mnem,
                op0_val,
                op1_val,
                op2_val,
                any_val,
                count,
                offset,
                max_scan_insns,
                {
                    key: str(pattern[field]).lower()
                    for key, field in ((0, "op0_text"), (1, "op1_text"), (2, "op2_text"), ("any", "op_any_text"))
                    if pattern.get(field)
                },
            )

            rows = []
            for addr_s in addresses:
                ea = int(addr_s, 16)
                row = {"addr": addr_s}
                if include_disasm:
                    row["disasm"] = disasm_text(ea)
                if include_fn:
                    row["fn"] = get_function(ea, raise_error=False)
                rows.append(row)

            summary["op0"] = op0_val
            summary["op1"] = op1_val
            summary["op2"] = op2_val
            summary["op_any"] = any_val

            results.append(
                {
                    "query": summary,
                    "ranges": [
                        {"start": hex(start_ea), "end": hex(end_ea)}
                        for start_ea, end_ea in ranges
                    ],
                    "matches": rows,
                    "count": len(rows),
                    "cursor": {"next": offset + count} if more else {"done": True},
                    "scanned": scanned,
                    "truncated": truncated,
                    "next_start": hex(next_start) if next_start is not None else None,
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "query": summary,
                    "ranges": [],
                    "matches": [],
                    "count": 0,
                    "cursor": {"done": True},
                    "scanned": 0,
                    "truncated": False,
                    "next_start": None,
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Export Operations
# ============================================================================


@tool
@idasync
def export_funcs(
    addrs: Annotated[list[str] | str, "Function addresses to export"],
    format: Annotated[
        str, "Export format: json (default), c_header, or prototypes"
    ] = "json",
) -> dict:
    """Legacy function exporter (no canonical equivalent).
    WHEN: dump function records (name, prototype, size, comments; json adds asm+decompile+xrefs).
    RETURNS: {format, functions[] | content(c_header) | functions[{name, prototype}](prototypes)}.
    LIMITS: format json|c_header|prototypes (default json); unknown functions return error entries."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": addr, "error": "Function not found"})
                continue

            func_data = {
                "addr": addr,
                "name": ida_funcs.get_func_name(func.start_ea),
                "prototype": get_prototype(func),
                "size": hex(func.end_ea - func.start_ea),
                "comments": get_all_comments(ea),
            }

            if format == "json":
                func_data["asm"] = get_assembly_lines(ea)
                (
                    func_data["code"],
                    func_data["decompile_error"],
                    func_data["decompile_error_details"],
                ) = _decompile_section(func)
                func_data["xrefs"] = _xrefs_section(func.start_ea)

            results.append(func_data)

        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    if format == "c_header":
        # Generate C header file
        lines = ["// Auto-generated by IDA Pro MCP", ""]
        for func in results:
            if "prototype" in func and func["prototype"]:
                lines.append(f"{func['prototype']};")
        return {"format": "c_header", "content": "\n".join(lines)}

    elif format == "prototypes":
        # Just prototypes
        prototypes = []
        for func in results:
            if "prototype" in func and func["prototype"]:
                prototypes.append(
                    {"name": func.get("name"), "prototype": func["prototype"]}
                )
        return {"format": "prototypes", "functions": prototypes}

    return {"format": "json", "functions": results}


# ============================================================================
# Graph Operations
# ============================================================================


_INDIRECT_CAP = 20
_PATH_EXPANSION_CAP = 5000


def _is_func_start(ea: int) -> bool:
    func = ida_funcs.get_func(ea)
    return func is not None and func.start_ea == ea


def _code_pointer_at(ea: int) -> int | None:
    """Function start stored in the pointer slot at *ea* (function-pointer globals)."""
    import ida_ida

    value = ida_bytes.get_qword(ea) if ida_ida.inf_is_64bit() else ida_bytes.get_dword(ea)
    return value if value and _is_func_start(value) else None


def _calls_out(func_ea: int, cap: int, include_indirect: bool) -> tuple[list, list, bool]:
    """([(site, callee, type)], unresolved indirect call sites, capped) for one function."""
    import ida_idp

    func = ida_funcs.get_func(func_ea)
    edges: list[tuple[int, int, str]] = []
    unresolved: list[dict] = []
    seen: set[int] = set()
    capped = False
    if func is None:
        return edges, unresolved, capped
    for site in idautils.FuncItems(func.start_ea):
        insn = _decode_insn_at(site)
        if insn is None or not ida_idp.is_call_insn(insn):
            continue
        op = insn.ops[0]
        if op.type in (ida_ua.o_near, ida_ua.o_far):
            targets, kind = [op.addr], "call"
        elif op.type == ida_ua.o_mem:
            pointee = _code_pointer_at(op.addr)
            targets, kind = ([pointee], "indirect") if pointee is not None else ([op.addr], "call")
        else:
            targets = [ref for ref in idautils.CodeRefsFrom(site, 0) if _is_func_start(ref)]
            kind = "indirect"
            if not targets and include_indirect and len(unresolved) < _INDIRECT_CAP:
                unresolved.append({"site": hex(site), "text": disasm_text(site)})
        if kind == "indirect" and not include_indirect:
            continue
        for target in targets:
            callee = ida_funcs.get_func(target)
            target = callee.start_ea if callee is not None else target
            if target in seen:
                continue
            if len(seen) >= cap:
                capped = True
                break
            seen.add(target)
            edges.append((site, target, kind))
    return edges, unresolved, capped


def _calls_in(ea: int, cap: int, include_indirect: bool) -> tuple[list, list, bool]:
    """([(site, caller, type)], address-taken references, capped) for one function or import."""
    import ida_idp
    from .hexrays_ctree import with_thunks

    edges: list[tuple[int, int, str]] = []
    taken: list[dict] = []
    seen: set[int] = set()
    capped = False
    for target in sorted(with_thunks(ea)):
        for xref in idautils.XrefsTo(target, 0):
            caller = ida_funcs.get_func(xref.frm)
            if caller is not None and caller.flags & ida_funcs.FUNC_THUNK:
                continue  # thunk hops are folded into with_thunks
            insn = _decode_insn_at(xref.frm) if caller is not None else None
            if insn is not None and ida_idp.is_call_insn(insn):
                if caller.start_ea in seen:
                    continue
                if len(seen) >= cap:
                    capped = True
                    continue
                seen.add(caller.start_ea)
                edges.append((xref.frm, caller.start_ea, "call"))
            elif include_indirect and not xref.iscode and len(taken) < _INDIRECT_CAP:
                row = {"site": hex(xref.frm), "text": disasm_text(xref.frm)}
                if caller is not None:
                    row["func"] = display_name(caller.start_ea)
                taken.append(row)
    return edges, taken, capped


def call_graph(
    root: str,
    direction: str = "callees",
    max_depth: int = 3,
    max_nodes: int = 1000,
    offset: int = 0,
    max_edges_per_func: int = 100,
    include_indirect: bool = True,
) -> dict:
    """Breadth-first call graph page from one root (caller holds the IDA main thread).

    Nodes are numbered in BFS order; a page is nodes [offset, offset+max_nodes)
    plus the edges those nodes expand, so depth is always the shortest hop count.
    """
    root_ea = parse_address(root)
    func = ida_funcs.get_func(root_ea)
    if func is not None:
        root_ea = func.start_ea
    elif direction == "callees":
        raise IDAError(f"Not a function: {root}")
    expand = _calls_out if direction == "callees" else _calls_in
    unresolved_key = "indirect_calls" if direction == "callees" else "address_taken"
    order = [root_ea]
    depth = {root_ea: 0}
    nodes: list[dict] = []
    edges: list[dict] = []
    capped_funcs: list[str] = []
    end = offset + max_nodes
    index = 0
    while index < len(order) and index < end:
        ea = order[index]
        in_page = index >= offset
        index += 1
        node: dict = {"addr": hex(ea), "name": display_name(ea), "depth": depth[ea]}
        is_func = ida_funcs.get_func(ea) is not None
        if not is_func:
            node["external"] = True
        if depth[ea] < max_depth and (is_func or direction == "callers"):
            found, unresolved, capped = expand(ea, max_edges_per_func, include_indirect)
            for site, other, kind in found:
                if other not in depth:
                    depth[other] = depth[ea] + 1
                    order.append(other)
                if in_page:
                    src, dst = (ea, other) if direction == "callees" else (other, ea)
                    edges.append({"from": hex(src), "to": hex(dst), "site": hex(site), "type": kind})
            if in_page and unresolved:
                node[unresolved_key] = unresolved
            if in_page and capped:
                capped_funcs.append(hex(ea))
        if in_page:
            nodes.append(node)
    result: dict = {
        "root": str(root),
        "addr": hex(root_ea),
        "name": display_name(root_ea),
        "nodes": nodes,
        "edges": edges,
        "max_edges_per_func": max_edges_per_func,
        "next_offset": end if len(order) > end else None,
    }
    if result["next_offset"] is not None:
        result["limit_reason"] = "nodes"
    if capped_funcs:
        result["per_func_capped"] = capped_funcs
    return result


def call_paths(
    source: str,
    target: str,
    max_depth: int = 3,
    max_paths: int = 10,
    max_edges_per_func: int = 100,
    include_indirect: bool = True,
) -> dict:
    """Shortest forward call paths source -> target (caller holds the IDA main thread)."""
    from .hexrays_ctree import with_thunks

    src = parse_address(source)
    func = ida_funcs.get_func(src)
    if func is None:
        raise IDAError(f"Not a function: {source}")
    src = func.start_ea
    dst = parse_address(target)
    dst_func = ida_funcs.get_func(dst)
    if dst_func is not None:
        dst = dst_func.start_ea
    goal = with_thunks(dst)
    parents: dict[int, list[tuple[int, int]]] = {src: []}
    depth = {src: 0}
    frontier = [src]
    hits = [src] if src in goal else []
    expanded = 0
    truncated = False
    while frontier and not hits and not truncated and depth[frontier[0]] < max_depth:
        next_frontier: list[int] = []
        for ea in frontier:
            if expanded >= _PATH_EXPANSION_CAP:
                truncated = True
                break
            expanded += 1
            for site, other, _kind in _calls_out(ea, max_edges_per_func, include_indirect)[0]:
                if other not in depth:
                    depth[other] = depth[ea] + 1
                    parents[other] = [(ea, site)]
                    next_frontier.append(other)
                elif depth[other] == depth[ea] + 1:
                    parents[other].append((ea, site))
        hits = [ea for ea in next_frontier if ea in goal]
        frontier = next_frontier

    paths: list[list[dict]] = []

    def walk(ea: int, suffix: list[dict]) -> None:
        if len(paths) >= max_paths:
            return
        if not parents[ea]:
            paths.append([{"addr": hex(ea), "name": display_name(ea)}, *suffix])
            return
        for parent, site in parents[ea]:
            walk(parent, [{"addr": hex(ea), "name": display_name(ea), "site": hex(site)}, *suffix])

    for hit in hits:
        walk(hit, [])
    result: dict = {
        "from": hex(src),
        "to": hex(dst),
        "paths": paths,
        "length": len(paths[0]) - 1 if paths else None,
    }
    if truncated or len(paths) >= max_paths:
        result["truncated"] = True
    return result


@tool
@idasync
def callgraph(
    roots: Annotated[
        list[str] | str, "Root function addresses to start call graph traversal from"
    ],
    max_depth: Annotated[int, "Maximum depth for call graph traversal (default: 5, max: 20)"] = 5,
    max_nodes: Annotated[
        int, "Max nodes per root page (default: 1000, max: 100000)"
    ] = 1000,
    max_edges_per_func: Annotated[
        int, "Max distinct callees per function (default: 200, max: 5000)"
    ] = 200,
) -> list[dict]:
    """Prefer graph_query(kind="calls", targets=..., max_depth=...) for canonical call graphs.
    WHEN: bounded breadth-first callee graph from root functions.
    RETURNS: [{root, addr, name, nodes[{addr, name, depth, external?, indirect_calls?}], edges[{from, to, site, type}], next_offset, limit_reason?, per_func_capped?, error?}].
    LIMITS: depth max 20, nodes max 100000, per-func callees max 5000; next_offset set when the node budget cut the graph."""
    max_depth = clamp_int(max_depth, 5, 0, 20)
    max_nodes = clamp_int(max_nodes, 1000, 1, 100000) if max_nodes > 0 else 100000
    max_edges_per_func = clamp_int(max_edges_per_func, 200, 1, 5000) if max_edges_per_func > 0 else 5000
    results = []
    for root in normalize_list_input(roots):
        try:
            results.append(call_graph(root, "callees", max_depth, max_nodes, 0, max_edges_per_func))
        except Exception as e:
            results.append({"root": root, "error": str(e), "nodes": [], "edges": []})
    return results
