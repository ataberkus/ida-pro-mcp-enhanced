"""Hex-Rays def-use extraction for dataflow_trace and taint_analyze.

IDA access stays inside ``idasync``; each function is lowered to a plain
"flow" dict (see ``ida_pro_mcp.vnext.analysis``) and the graph algorithms run
on those dicts, so they stay testable without IDAPython.
"""

from __future__ import annotations

import bisect
import re
from typing import Any, Callable

from ida_pro_mcp.vnext import analysis
from ida_pro_mcp.vnext.contracts import AnalysisEngine, AnalysisGraph, ErrorCode, VNextError

from .sync import IDAError, idasync, tool_timeout

_MAX_FUNCTIONS = 20
_MAX_API_CALLERS = 50
_ANCHOR_INDEX = 0x1FFFFFFF
_ANCHOR_NOT_CITEM = 0xE0000000  # ANCHOR_LVAR | ANCHOR_ITP | ANCHOR_BLKCMT
_UNSUPPORTED = [
    {"kind": "memory_alias", "reason": "stores and loads through pointers are joined conservatively as one memory location"},
    {"kind": "concurrent_memory", "reason": "reaching definitions are single-threaded"},
]


def _hexrays():
    from .hexrays_ctree import _hexrays as load

    return load()


def _parse(text: str) -> int:
    """parse_address with its did-you-mean message surfaced as INVALID_OPERATION."""
    from .utils import parse_address

    try:
        return parse_address(text)
    except IDAError as exc:
        raise VNextError(ErrorCode.INVALID_OPERATION, str(exc)) from exc


def _split_variable(text: str, variable: str | None) -> tuple[int, str | None]:
    """Resolve ``addr`` (or ``func:var`` when no explicit variable) to (ea, variable)."""
    try:
        return _parse(text), variable
    except VNextError:
        if variable is not None or ":" not in text:
            raise
    func_part, var = text.rsplit(":", 1)
    return _parse(func_part), var.strip() or None


def _is_user_function(func: Any) -> bool:
    import ida_funcs
    import ida_segment

    if func is None or func.flags & (ida_funcs.FUNC_THUNK | ida_funcs.FUNC_LIB):
        return False
    seg = ida_segment.getseg(func.start_ea)
    return seg is None or seg.type != ida_segment.SEG_XTRN


def _is_function_target(ea: int) -> bool:
    """Function starts and imports are matched as callees, not statement addresses."""
    import ida_segment

    from . import compat

    func = compat.get_func(ea)
    if func is not None:
        return int(func.start_ea) == ea
    seg = ida_segment.getseg(ea)
    return seg is not None and seg.type == ida_segment.SEG_XTRN


def _line_map(cfunc: Any, hr: Any) -> tuple[list[str], dict[int, int]]:
    """Pseudocode lines (tags stripped) and ea -> line index.

    Expression items win over statements: a do-while's condition belongs on the
    ``while`` line, not the ``do`` line the statement is anchored on.
    """
    import ida_lines
    import idaapi

    anchor = re.compile(
        re.escape(ida_lines.SCOLOR_ON + ida_lines.SCOLOR_ADDR)
        + "([0-9A-Fa-f]{%d})" % ida_lines.COLOR_ADDR_SIZE
    )
    texts: list[str] = []
    item_line: dict[int, int] = {}
    for number, line in enumerate(cfunc.get_pseudocode()):
        texts.append(ida_lines.tag_remove(line.line).strip())
        for match in anchor.finditer(line.line):
            value = int(match.group(1), 16)
            if not value & _ANCHOR_NOT_CITEM:
                item_line.setdefault(value & _ANCHOR_INDEX, number)
    ranked: dict[int, tuple[int, int]] = {}
    for item in cfunc.treeitems:
        number = item_line.get(item.index)
        ea = int(item.ea)
        if number is None or ea == idaapi.BADADDR or item.op == hr.cit_block:
            continue
        rank = 0 if item.is_expr() else 1
        if ea not in ranked or rank < ranked[ea][0]:
            ranked[ea] = (rank, number)
    return texts, {ea: number for ea, (_rank, number) in ranked.items()}


def _lvar_name(lvar: Any, index: int) -> str:
    if lvar.name:
        return str(lvar.name)
    try:
        import ida_hexrays

        return f"<{ida_hexrays.print_vdloc(lvar.location, int(lvar.width))}>"
    except Exception:
        return f"<tmp{index}>"


def build_flow(func_ea: int) -> dict[str, Any]:
    """Lower one function's MMAT_LVARS microcode to a flow dict (caller holds the main thread)."""
    import idaapi
    import idautils

    from .utils import DecompilationError, decompile_checked, display_name

    hr = _hexrays()
    try:
        cfunc = decompile_checked(func_ea)
    except DecompilationError as exc:
        raise VNextError(
            ErrorCode.NOT_SUPPORTED,
            f"Hex-Rays could not decompile {hex(func_ea)}",
            details={"reason": str(exc)},
        ) from exc
    lvars = cfunc.get_lvars()
    variables: dict[str, dict[str, str]] = {}

    def lvar_key(index: int) -> str:
        key = f"l{index}"
        if key not in variables:
            lvar = lvars[index]
            domain = "stack" if lvar.location.is_stkoff() else "register"
            variables[key] = {"name": _lvar_name(lvar, index), "domain": domain}
        return key

    def global_key(ea: int) -> str:
        key = f"g{ea:x}"
        if key not in variables:
            variables[key] = {"name": display_name(ea) or hex(ea), "domain": "global"}
        return key

    def mem_key() -> str:
        variables.setdefault("mem", {"name": "memory", "domain": "memory"})
        return "mem"

    call_ops = (hr.m_call, hr.m_icall)

    def walk(op: Any, uses: list[str], info: dict[str, Any]) -> None:
        kind = op.t
        if kind == hr.mop_l:
            uses.append(lvar_key(int(op.l.idx)))
        elif kind == hr.mop_v:
            uses.append(global_key(int(op.g)))
        elif kind == hr.mop_a:
            walk(op.a, uses, info)
        elif kind == hr.mop_d:
            insn(op.d, uses, info, top=False)
        elif kind == hr.mop_f:
            for arg in op.f.args:
                walk(arg, uses, info)
        elif kind == hr.mop_p:
            walk(op.pair.lop, uses, info)
            walk(op.pair.hop, uses, info)

    def insn(ins: Any, uses: list[str], info: dict[str, Any], top: bool) -> None:
        opcode = ins.opcode
        if opcode in call_ops:
            callee = int(ins.l.g) if opcode == hr.m_call and ins.l.t == hr.mop_v else None
            if opcode == hr.m_icall:
                walk(ins.r, uses, info)
            args: list[list[str]] = []
            if ins.d.t == hr.mop_f:
                for arg in ins.d.f.args:
                    keys: list[str] = []
                    walk(arg, keys, info)
                    args.append(keys)
                    uses.extend(keys)
                    base = arg.a if arg.t == hr.mop_a else arg
                    if base.t == hr.mop_l and (arg.t == hr.mop_a or arg.type.is_ptr()):
                        # The callee may write through the pointer: a MAY definition.
                        info["defs"].append((lvar_key(int(base.l.idx)), False))
            info["calls"].append({"callee": callee, "args": args})
            return
        if opcode == hr.m_stx:
            info["defs"].append((mem_key(), False))
            for op in (ins.l, ins.r, ins.d):
                walk(op, uses, info)
            return
        if opcode == hr.m_ldx:
            uses.append(mem_key())
        walk(ins.l, uses, info)
        walk(ins.r, uses, info)
        dest = ins.d
        if top and ins.modifies_d() and dest.t in (hr.mop_l, hr.mop_v):
            if dest.t == hr.mop_l:
                lvar = lvars[int(dest.l.idx)]
                full = int(dest.l.off) == 0 and int(dest.size) >= int(lvar.width)
                info["defs"].append((lvar_key(int(dest.l.idx)), full))
            else:
                info["defs"].append((global_key(int(dest.g)), True))
        elif not ins.modifies_d():
            walk(dest, uses, info)

    texts, ea_line = _line_map(cfunc, hr)
    params = [lvar_key(int(index)) for index in cfunc.argidx]
    # instruction 0 is the synthetic function entry defining every parameter.
    instructions: list[dict[str, Any]] = [
        {"ea": func_ea, "defs": [(key, True) for key in params], "uses": [], "calls": [], "text": "entry"}
    ]
    mba = cfunc.mba
    blocks: list[tuple[list[int], list[int]]] = []
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        ids: list[int] = []
        ins = block.head
        while ins is not None:
            info: dict[str, Any] = {"defs": [], "calls": []}
            uses: list[str] = []
            insn(ins, uses, info, top=True)
            ids.append(len(instructions))
            instructions.append(
                {"ea": int(ins.ea), "defs": info["defs"], "uses": uses, "calls": info["calls"], "text": str(ins.dstr())}
            )
            ins = ins.next
        blocks.append((ids, [int(pred) for pred in block.predset]))

    # Reaching definitions: a definition is (instruction, key, must).
    def transfer(state: set, index: int) -> set:
        for key, must in instructions[index]["defs"]:
            if must:
                state = {item for item in state if item[1] != key}
            state = state | {(index, key, must)}
        return state

    entry_defs = transfer(set(), 0)
    block_in = [set() for _ in blocks]
    block_out = [set() for _ in blocks]
    for _ in range(max(1, len(blocks) * 4)):
        changed = False
        for serial, (ids, preds) in enumerate(blocks):
            incoming = set(entry_defs) if serial == 0 else set()
            for pred in preds:
                incoming |= block_out[pred]
            current = incoming
            for index in ids:
                current = transfer(current, index)
            if incoming != block_in[serial] or current != block_out[serial]:
                block_in[serial], block_out[serial] = incoming, current
                changed = True
        if not changed:
            break
    raw_edges: list[tuple[int, int, str, bool]] = []
    for serial, (ids, _preds) in enumerate(blocks):
        current = block_in[serial]
        for index in ids:
            used = set(instructions[index]["uses"])
            for prior, key, must in current:
                if key in used:
                    raw_edges.append((prior, index, key, must))
            current = transfer(current, index)

    # One node per instruction address (Hex-Rays may emit several per ea).
    line_eas = sorted(ea_line)

    def line_of(ea: int) -> int | None:
        if ea in ea_line:
            return ea_line[ea]
        position = bisect.bisect_right(line_eas, ea) - 1
        return ea_line[line_eas[position]] if position >= 0 else None

    nodes: list[dict[str, Any]] = []
    node_of: list[int] = []
    by_ea: dict[int, int] = {}
    for index, ins in enumerate(instructions):
        ea = ins["ea"]
        address = None if ea == idaapi.BADADDR else ea
        target = by_ea.get(address) if address is not None and index else None
        if target is None:
            target = len(nodes)
            if address is not None and index:
                by_ea[address] = target
            line_no = 0 if index == 0 else (line_of(address) if address is not None else None)
            nodes.append(
                {
                    "address": address,
                    "line_no": line_no,
                    "line": texts[line_no] if line_no is not None and line_no < len(texts) else "",
                    "defines": [],
                    "uses": [],
                    "calls": [],
                    "microcode": [],
                }
            )
        node = nodes[target]
        node["defines"].extend(key for key, _must in ins["defs"] if key not in node["defines"])
        node["uses"].extend(key for key in dict.fromkeys(ins["uses"]) if key not in node["uses"])
        node["calls"].extend(ins["calls"])
        node["microcode"].append(ins["text"])
        node_of.append(target)
    for node in nodes:
        node["microcode"] = "; ".join(node["microcode"])

    edges: dict[tuple[int, int, str], str] = {}
    for prior, index, key, must in raw_edges:
        source, target = node_of[prior], node_of[index]
        if source == target and prior != index:
            continue  # collapsed into one node; a real self-loop keeps prior == index
        edge = (source, target, key)
        if must or edges.get(edge) != "must":
            edges[edge] = "must" if must else edges.get(edge, "may")
    return {
        "func": int(func_ea),
        "name": display_name(func_ea),
        "vars": variables,
        "params": params,
        "nodes": nodes,
        "edges": [[source, target, key, kind] for (source, target, key), kind in edges.items()],
        "line_of": {int(ea): line_of(int(ea)) for ea in idautils.FuncItems(func_ea)},
    }


def _containing_function(ea: int, what: str) -> int:
    from . import compat

    func = compat.get_func(ea)
    if func is None:
        # Globals/imports have no microcode; dataflow_trace falls back to reference flow.
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Address is not inside a function: {what}")
    return int(func.start_ea)


def _variable_keys(flow: dict[str, Any], variable: str) -> list[str]:
    keys = [key for key, var in flow["vars"].items() if key.startswith("l") and var["name"] == variable]
    if not keys:
        names = sorted({var["name"] for key, var in flow["vars"].items() if key.startswith("l") and not var["name"].startswith("<")})
        raise VNextError(
            ErrorCode.INVALID_OPERATION,
            f"Unknown variable {variable!r} in {flow['name']}; variables: {', '.join(names) or '(none)'}",
            details={"function": flow["name"], "variables": names},
        )
    return keys


def _address_seeds(flow: dict[str, Any], ea: int) -> tuple[list[int], str | None]:
    """Nodes at ea, else nodes on ea's pseudocode line, else the nearest node."""
    nodes = flow["nodes"]
    exact = [index for index, node in enumerate(nodes) if index and node["address"] == ea]
    if exact:
        return exact, None
    line_no = flow["line_of"].get(ea)
    same_line = [index for index, node in enumerate(nodes) if index and line_no is not None and node["line_no"] == line_no]
    if same_line:
        return same_line, None
    addressed = [(abs(node["address"] - ea), index) for index, node in enumerate(nodes) if index and node["address"] is not None]
    if not addressed:
        return [], f"{hex(ea)} has no data-flow nodes"
    index = min(addressed)[1]
    return [index], f"{hex(ea)} is not a data-flow node; using nearest node {hex(nodes[index]['address'])}"


@idasync
@tool_timeout(120.0)
def trace_function(
    addr: str,
    *,
    variable: str | None = None,
    direction: str = "forward",
    max_depth: int = 3,
    include_microcode: bool = False,
) -> dict[str, Any]:
    """Seeded intraprocedural def-use graph with readable nodes."""
    if direction not in {"forward", "backward", "both"}:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"Invalid data-flow direction: {direction}")
    ea, var = _split_variable(addr, variable)
    func_ea = _containing_function(ea, addr)
    flow = build_flow(func_ea)
    warnings: list[str] = []
    if var is not None:
        seeds = analysis.variable_seeds(flow, _variable_keys(flow, var), direction)
    elif ea == func_ea:
        seeds = analysis.address_seeds([0], direction)
    else:
        indexes, warning = _address_seeds(flow, ea)
        seeds = analysis.address_seeds(indexes, direction)
        if warning:
            warnings.append(warning)
    nodes, edges, truncated = analysis.trace_graph(flow, seeds, max(0, max_depth), include_microcode)
    return AnalysisGraph(
        engine=AnalysisEngine.HEXRAYS_MICROCODE,
        fidelity="semantic_intraprocedural",
        nodes=nodes,
        edges=edges,
        unsupported_edges=[
            {"kind": "interprocedural", "reason": "values passed to calls are not followed into callees (use taint_analyze)"},
            *_UNSUPPORTED,
        ],
        warnings=warnings,
        truncated=truncated,
    ).to_dict()


def _resolve_target(token: str) -> dict[str, Any]:
    from .hexrays_ctree import with_thunks

    ea = _parse(token)
    if _is_function_target(ea):
        return {"token": token, "addrs": set(), "callees": with_thunks(ea)}
    return {"token": token, "addrs": {ea}, "callees": set()}


def _source_seeds(
    token: str,
    load: Callable[[int], dict[str, Any] | None],
    warnings: list[str],
) -> list[dict[str, Any]]:
    import idautils

    from . import compat
    from .hexrays_ctree import _callers_of, with_thunks

    ea, var = _split_variable(token, None)
    func = compat.get_func(ea)
    if var is not None or (func is not None and _is_user_function(func)):
        if func is None:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"{token!r}: variables need an address inside a function")
        flow = load(int(func.start_ea))
        if flow is None:
            return []
        if var is not None:
            keys = _variable_keys(flow, var)
            # A restricted seed propagates only the variable's own definitions;
            # an uninitialised variable taints its uses instead.
            return [
                {"func": flow["func"], "node": node, "var": None if out else keys[0], "out": out}
                for node, out, _way in analysis.variable_seeds(flow, keys, "forward")
            ]
        if int(func.start_ea) == ea:
            if not flow["params"]:
                warnings.append(f"Source {token!r}: {flow['name']} has no parameters to seed")
            return [{"func": flow["func"], "node": 0, "var": None, "out": frozenset(flow["params"])}]
        indexes, warning = _address_seeds(flow, ea)
        if warning:
            warnings.append(f"Source {token!r}: {warning}")
        return [{"func": flow["func"], "node": index, "var": None, "out": None} for index in indexes]

    if _is_function_target(ea):
        # API/import: the value returned by, and buffers written by, each call site.
        targets = with_thunks(ea)
        seeds = []
        for caller in sorted(_callers_of(targets))[:_MAX_API_CALLERS]:
            flow = load(caller)
            if flow is None:
                continue
            for index, node in enumerate(flow["nodes"]):
                if any(call["callee"] in targets for call in node["calls"]):
                    seeds.append({"func": caller, "node": index, "var": None, "out": None})
        if not seeds:
            warnings.append(f"Source {token!r}: no decompiled call sites")
        return seeds

    # Global data: every decompiled use of the global.
    key = f"g{ea:x}"
    seeds = []
    referrers = {int(f.start_ea) for xref in idautils.XrefsTo(ea) if (f := compat.get_func(xref.frm)) is not None}
    for func_ea in sorted(referrers):
        flow = load(func_ea)
        if flow is None:
            continue
        seeds.extend(
            {"func": func_ea, "node": index, "var": key, "out": None}
            for index, node in enumerate(flow["nodes"])
            if key in node["uses"]
        )
    if not seeds:
        warnings.append(f"Source {token!r}: no decompiled uses of {hex(ea)}")
    return seeds


@idasync
@tool_timeout(120.0)
def taint(
    sources: list[str],
    sinks: list[str],
    sanitizers: list[str],
    *,
    max_hops: int,
    max_paths: int,
    domains: set[str],
) -> dict[str, Any]:
    """Interprocedural (bounded) source->sink propagation over per-function flows."""
    from . import compat

    _hexrays()
    sink_specs = [_resolve_target(token) for token in sinks]
    warnings: list[str] = []
    sanitizer_specs = []
    for token in sanitizers:
        try:
            sanitizer_specs.append(_resolve_target(token))
        except VNextError as exc:
            warnings.append(f"Sanitizer ignored: {exc}")
    flows: dict[int, dict[str, Any] | None] = {}
    capped: list[bool] = [False]

    def load(func_ea: int) -> dict[str, Any] | None:
        if func_ea in flows:
            return flows[func_ea]
        if not _is_user_function(compat.get_func(func_ea)):
            return None
        if len(flows) >= _MAX_FUNCTIONS:
            capped[0] = True
            return None
        try:
            flows[func_ea] = build_flow(func_ea)
        except VNextError as exc:
            flows[func_ea] = None
            warnings.append(f"{hex(func_ea)} skipped: {exc}")
        return flows[func_ea]

    seeds = []
    for source in sources:
        seeds.extend({"source": source, **seed} for seed in _source_seeds(source, load, warnings))
    result = analysis.propagate_taint(
        load,
        seeds,
        sinks=sink_specs,
        sanitizers=sanitizer_specs,
        domains=domains,
        max_hops=max(0, max_hops),
        max_paths=max_paths,
    )
    if capped[0]:
        warnings.append(f"Stopped loading functions at the {_MAX_FUNCTIONS}-function cap")
    result["warnings"] = warnings + result["warnings"]
    result["truncated"] = result["truncated"] or capped[0]
    result["functions_analyzed"] = sorted(flow["name"] for flow in flows.values() if flow is not None)
    return result
