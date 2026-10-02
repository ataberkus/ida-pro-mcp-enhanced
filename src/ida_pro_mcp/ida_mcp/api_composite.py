"""Composite analysis tools that aggregate multiple data sources."""

from __future__ import annotations

from collections import defaultdict
from typing import Annotated

import ida_funcs

from .rpc import tool
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    parse_address,
    display_name,
    get_prototype,
    get_callees,
    get_callers,
    get_all_comments,
    extract_function_strings,
    extract_function_constants,
    decompile_function_safe,
    get_assembly_lines,
    normalize_list_input,
    _collect_callees,
    _collect_callers,
)
from .api_analysis import _capped, _display_rows, _xrefs_section, decompile_excerpt

# Default statement lines in the decompile excerpt (declarations not counted).
_DECOMPILE_BODY_LINES = 120
# Cap for callers/callees/xrefs-per-side/comments lists.
_LIST_CAP = 50
# Max strings/constants returned in compact mode.
_TOP_STRINGS = 10
_TOP_CONSTANTS = 10
# Constants filtered out of extract_function_constants results.
_BORING_CONSTANTS = frozenset({0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})


# ---------------------------------------------------------------------------
# Internal helpers (no @tool — called from within @idasync context)
# ---------------------------------------------------------------------------

def _basic_block_info(ea: int) -> dict:
    """Return block count and cyclomatic complexity for the function at *ea*."""
    import idaapi

    func = ida_funcs.get_func(ea)
    if func is None:
        return {"count": 0, "cyclomatic_complexity": 0}

    fc = idaapi.FlowChart(func)
    nodes = 0
    edges = 0
    for block in fc:
        nodes += 1
        for _ in block.succs():
            edges += 1

    return {"count": nodes, "cyclomatic_complexity": edges - nodes + 2}


def _filter_constants(raw: list[dict], limit: int = _TOP_CONSTANTS) -> list[dict]:
    """Drop boring constants, return top N by absolute value."""
    out = []
    for c in raw:
        val = c.get("value", 0)
        if not isinstance(val, int):
            continue
        if abs(val) < 0x100 or val in _BORING_CONSTANTS:
            continue
        out.append(c)
    out.sort(key=lambda c: abs(c.get("value", 0)) if isinstance(c.get("value"), int) else 0, reverse=True)
    return out[:limit]


def _compact_strings(raw: list[dict], limit: int = _TOP_STRINGS) -> list[str]:
    """Return just the string values, deduplicated, capped at limit."""
    seen: set[str] = set()
    out: list[str] = []
    for s in raw:
        val = s.get("value") or s.get("string", "")
        if val and val not in seen:
            seen.add(val)
            out.append(val)
            if len(out) >= limit:
                break
    return out


def _compact_callees(raw: list[dict]) -> list[str]:
    """Return just callee display names (address when unnamed)."""
    return [display_name(int(c["addr"], 16)) for c in raw]


def _analyze_function_internal(
    ea: int,
    *,
    include_asm: bool = False,
    include_declarations: bool = False,
    include_comments: bool = False,
    max_lines: int = _DECOMPILE_BODY_LINES,
) -> dict:
    """Core analysis logic — must be called from an @idasync context.

    Compact by default: decompile excerpt of max_lines statement lines (locals
    summarized as a count), top strings/constants, capped callers/callees/xrefs,
    no comments, no disassembly."""
    result: dict = {"addr": hex(ea), "error": None}

    try:
        func = ida_funcs.get_func(ea)
        if func is None:
            result["error"] = f"No function at {hex(ea)}"
            return result
        ea = func.start_ea
        result["addr"] = hex(ea)
        result["name"] = display_name(ea)
        result["prototype"] = get_prototype(func)
        result["size"] = func.end_ea - func.start_ea

        code = decompile_function_safe(ea)
        if code is None:
            result["decompiled"] = None
        else:
            result.update(decompile_excerpt(code, max_lines, include_declarations))

        if include_asm:
            result["assembly"] = get_assembly_lines(ea)

        result["strings"] = _compact_strings(extract_function_strings(ea))
        result["constants"] = _filter_constants(extract_function_constants(ea))
        for section in (
            _capped("callees", "callee_count", _collect_callees(func, call_only=True), _LIST_CAP),
            _capped("callers", "caller_count", _collect_callers(func), _LIST_CAP),
        ):
            result.update(section)
        result["callees"] = _display_rows(result["callees"])
        result["callers"] = _display_rows(result["callers"])
        result["xrefs"] = _xrefs_section(ea, _LIST_CAP)
        if include_comments:
            comments = get_all_comments(ea)
            result["comments"] = dict(list(comments.items())[:_LIST_CAP])
            result["comment_count"] = len(comments)
        result["basic_blocks"] = _basic_block_info(ea)

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Tool 1 — analyze_function
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(120.0)
def analyze_function(
    addr: Annotated[str, "Function address or name"],
    include_asm: Annotated[bool, "Include full disassembly (default: false, saves tokens)"] = False,
    include_declarations: Annotated[bool, "Keep local-variable declarations in the excerpt"] = False,
    include_comments: Annotated[bool, "Include instruction comments (IDA auto-comments included)"] = False,
    max_lines: Annotated[int, "Statement lines in the decompile excerpt (default 120)"] = _DECOMPILE_BODY_LINES,
) -> dict:
    """Prefer analysis_run(mode="function", targets=[addr], ...) for canonical single-function analysis.
    WHEN: compact single-function brief (pseudocode excerpt, top strings/constants, callers/callees, xrefs, block metrics).
    RETURNS: {addr, name, prototype, size, decompiled, declarations, decompile_truncated, next_line_offset, strings, constants, callers[{addr,name}], caller_count, callees[{addr,name}], callee_count, xrefs{to,from,*_count}, comments?, basic_blocks, error}.
    LIMITS: excerpt = header + max_lines statement lines; lists capped at 50 with totals; pass include_asm=true only for raw instructions."""

    try:
        ea = parse_address(addr)
    except IDAError as exc:
        return {"addr": addr, "error": str(exc)}

    return _analyze_function_internal(
        ea,
        include_asm=include_asm,
        include_declarations=include_declarations,
        include_comments=include_comments,
        max_lines=max(0, int(max_lines)),
    )


# ---------------------------------------------------------------------------
# Tool 2 — analyze_component
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(180.0)
def analyze_component(
    addrs: Annotated[list[str] | str, "Function addresses (comma-separated or list)"],
) -> dict:
    """Prefer analysis_run(mode="component", targets=[...], ...) for canonical component analysis.
    WHEN: compact briefs for a cluster of related functions plus internal call graph, shared globals, interface classification.
    RETURNS: {functions[{addr, name, prototype, size, callees, strings, basic_blocks, complexity}], nodes?, edges?, shared_globals?, error?}.
    LIMITS: per-function summaries are compact (no full decompile); unresolvable inputs return an error entry."""

    import idaapi
    import idautils

    raw = normalize_list_input(addrs)
    if not raw:
        return {"error": "Empty address list"}

    ea_map: dict[int, str] = {}
    for a in raw:
        try:
            ea_map[parse_address(a)] = a
        except IDAError as exc:
            return {"error": str(exc)}

    ea_set = set(ea_map.keys())

    # --- Per-function COMPACT summary (no decompile, no disasm) ---
    functions: list[dict] = []
    for ea in ea_set:
        func = ida_funcs.get_func(ea)
        if func is None:
            mapped = bool(idaapi.is_loaded(ea))
            reason = "function_not_defined" if mapped else "address_not_mapped"
            entry = {
                "input": ea_map[ea],
                "addr": hex(ea),
                "reason": reason,
                "error": (
                    f"No function is defined at {hex(ea)}"
                    if mapped
                    else f"Address {hex(ea)} is not mapped in the database"
                ),
            }
            if mapped:
                entry["fallback"] = {"tool": "disassemble", "addr": hex(ea)}
            functions.append(entry)
            continue
        name = display_name(ea)
        strings_raw = extract_function_strings(ea)
        top_strings = _compact_strings(strings_raw, limit=5)
        callee_list = _compact_callees(get_callees(hex(ea)))
        bb = _basic_block_info(ea)
        functions.append({
            "addr": hex(ea),
            "name": name,
            "prototype": get_prototype(func),
            "size": func.end_ea - func.start_ea,
            "callees": callee_list,
            "strings": top_strings,
            "basic_blocks": bb["count"],
            "complexity": bb["cyclomatic_complexity"],
        })

    # --- Internal call graph ---
    nodes = [hex(ea) for ea in ea_set]
    edges: list[dict] = []
    for ea in ea_set:
        for callee in (get_callees(hex(ea)) or []):
            callee_ea = callee.get("addr")
            if isinstance(callee_ea, str):
                try:
                    callee_ea = int(callee_ea, 16)
                except (ValueError, TypeError):
                    continue
            if callee_ea in ea_set:
                edges.append({
                    "from": hex(ea),
                    "to": hex(callee_ea),
                    "name": display_name(callee_ea),
                })

    # --- Shared globals ---
    func_globals: dict[int, set[int]] = {}
    for ea in ea_set:
        globals_accessed: set[int] = set()
        func = ida_funcs.get_func(ea)
        if func is None:
            func_globals[ea] = globals_accessed
            continue
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.iscode:
                    continue
                ref_func = ida_funcs.get_func(xref.to)
                if ref_func is None and idaapi.is_loaded(xref.to):
                    globals_accessed.add(xref.to)
        func_globals[ea] = globals_accessed

    global_refcount: dict[int, list[str]] = defaultdict(list)
    for ea, gset in func_globals.items():
        fname = display_name(ea)
        for g in gset:
            global_refcount[g].append(fname)

    shared_globals = []
    for g_ea, accessors in sorted(global_refcount.items()):
        if len(accessors) >= 2:
            shared_globals.append({
                "addr": hex(g_ea),
                "name": display_name(g_ea),
                "accessed_by": sorted(accessors),
            })

    # --- Interface vs internal ---
    interface_functions: list[str] = []
    internal_only: list[str] = []
    for ea in ea_set:
        callers = get_callers(hex(ea))
        has_external = False
        for c in (callers or []):
            caller_addr = c.get("addr") or c.get("start_ea")
            if isinstance(caller_addr, str):
                try:
                    caller_addr = int(caller_addr, 16)
                except (ValueError, TypeError):
                    has_external = True
                    break
            if caller_addr not in ea_set:
                has_external = True
                break
        if has_external:
            interface_functions.append(hex(ea))
        else:
            internal_only.append(hex(ea))

    # --- String usage across functions ---
    string_funcs: dict[str, set[str]] = defaultdict(set)
    for ea in ea_set:
        fname = display_name(ea)
        for s in (extract_function_strings(ea) or []):
            sval = s.get("value") or s.get("string", "")
            if sval:
                string_funcs[sval].add(fname)

    string_usage = {
        s: sorted(fnames)
        for s, fnames in sorted(string_funcs.items())
        if len(fnames) >= 2
    }

    return {
        "functions": functions,
        "internal_call_graph": {"nodes": nodes, "edges": edges},
        "shared_globals": shared_globals,
        "interface_functions": interface_functions,
        "internal_only": internal_only,
        "string_usage": string_usage,
    }


# ---------------------------------------------------------------------------
# Tool 3 — trace_data_flow
# ---------------------------------------------------------------------------

_MAX_TRACE_NODES = 200
_MAX_TRACE_EDGES = 500



@tool
@idasync
@tool_timeout(120.0)
def trace_data_flow(
    addr: Annotated[str, "Starting address"],
    direction: Annotated[str, "'forward' (xrefs from) or 'backward' (xrefs to)"] = "forward",
    max_depth: Annotated[int, "Maximum traversal depth"] = 5,
) -> dict:
    """Prefer dataflow_trace(addr, direction=..., max_depth=...) for canonical ref-flow traces.
    WHEN: multi-hop xref BFS from an address (forward=xrefs-from, backward=xrefs-to) with per-node func/instruction/type.
    RETURNS: {start, direction, depth_reached, nodes[{addr, func, instruction, type, name, depth}], edges[{from, to, type}], truncated, error?}.
    LIMITS: max_depth max 20; 200 nodes / 500 edges max (truncated set); bad direction returns an error dict. Keep .lower() normalization."""

    import idaapi
    import idautils
    import idc
    from collections import deque

    if direction not in ("forward", "backward", "both"):
        return {"error": f"direction must be 'forward', 'backward', or 'both', got {direction!r}"}

    try:
        start_ea = parse_address(addr)
    except IDAError as exc:
        return {"error": str(exc)}

    if max_depth < 1:
        max_depth = 1
    if max_depth > 20:
        max_depth = 20

    visited: set[int] = set()
    nodes: list[dict] = []
    edges: list[dict] = []
    depth_reached = 0

    # BFS queue: (ea, depth)
    queue: deque[tuple[int, int]] = deque()
    queue.append((start_ea, 0))
    visited.add(start_ea)

    while queue and len(nodes) < _MAX_TRACE_NODES:
        ea, depth = queue.popleft()
        if depth > max_depth:
            continue
        if depth > depth_reached:
            depth_reached = depth

        # Build node info.
        func = ida_funcs.get_func(ea)
        func_name = idaapi.get_func_name(ea) if func else None
        insn_text = idc.GetDisasm(ea) if idaapi.is_loaded(ea) else None

        # Determine if this address references a global/string.
        name_at = idaapi.get_name(ea)
        node_type = "code"
        if func is None and idaapi.is_loaded(ea):
            node_type = "data"

        nodes.append({
            "addr": hex(ea),
            "func": func_name,
            "instruction": insn_text,
            "type": node_type,
            "name": name_at if name_at else None,
            "depth": depth,
        })

        if depth >= max_depth:
            continue

        hops: list[tuple[int, str]] = []
        if direction in ("forward", "both"):
            hops.extend((xref.to, "code" if xref.iscode else "data") for xref in idautils.XrefsFrom(ea, 0))
        if direction in ("backward", "both"):
            hops.extend((xref.frm, "code" if xref.iscode else "data") for xref in idautils.XrefsTo(ea, 0))

        for target, xtype in hops:
            if len(edges) >= _MAX_TRACE_EDGES:
                break
            edges.append({
                "from": hex(ea),
                "to": hex(target),
                "type": xtype,
            })
            if target not in visited and len(nodes) + len(queue) < _MAX_TRACE_NODES:
                visited.add(target)
                queue.append((target, depth + 1))

    truncated = bool(queue) or len(nodes) >= _MAX_TRACE_NODES or len(edges) >= _MAX_TRACE_EDGES
    return {
        "start": hex(start_ea),
        "direction": direction,
        "depth_reached": depth_reached,
        "nodes": nodes,
        "edges": edges,
        "truncated": truncated,
    }
