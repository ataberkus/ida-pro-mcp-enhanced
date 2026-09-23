"""Composite analysis tools that aggregate multiple data sources."""

from __future__ import annotations

from collections import defaultdict
from typing import Annotated

import ida_funcs

from .rpc import tool, unsafe
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    parse_address,
    get_prototype,
    get_callees,
    get_callers,
    get_all_xrefs,
    get_all_comments,
    extract_function_strings,
    extract_function_constants,
    decompile_function_safe,
    get_assembly_lines,
    normalize_list_input,
)

# Max decompile lines before truncation.
_DECOMPILE_LINE_CAP = 100
# Max strings/constants returned in compact mode.
_TOP_STRINGS = 10
_TOP_CONSTANTS = 10
# Constants filtered out of extract_function_constants results.
_BORING_CONSTANTS = frozenset({0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})


# ---------------------------------------------------------------------------
# Internal helpers (no @tool — called from within @idasync context)
# ---------------------------------------------------------------------------

def _resolve_addr(addr: str) -> int:
    """Resolve address or name to ea. Raises IDAError on failure."""
    from .utils import resolve_address_or_name

    return resolve_address_or_name(addr)


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


def _cap_decompile(code: str | None) -> tuple[str | None, int | None]:
    """Cap decompiled output at _DECOMPILE_LINE_CAP lines.
    Returns (possibly_truncated_code, total_lines_or_None)."""
    if code is None:
        return None, None
    lines = code.split("\n")
    total = len(lines)
    if total <= _DECOMPILE_LINE_CAP:
        return code, None  # not truncated
    truncated = "\n".join(lines[:_DECOMPILE_LINE_CAP])
    return truncated, total


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
    """Return just callee names/addresses as strings."""
    return [c.get("name") or c.get("addr", "?") for c in raw]


def _analyze_function_internal(ea: int, *, include_asm: bool = False) -> dict:
    """Core analysis logic — must be called from an @idasync context.

    Returns a compact response by default: decompilation capped at 100 lines,
    top 10 strings as values only, top 10 non-trivial constants, no disassembly.
    Pass include_asm=True to include full disassembly."""
    import idaapi

    result: dict = {"addr": hex(ea), "error": None}

    try:
        func = ida_funcs.get_func(ea)
        if func is None:
            result["error"] = f"No function at {hex(ea)}"
            return result

        result["name"] = idaapi.get_func_name(ea) or ""
        result["prototype"] = get_prototype(func)
        result["size"] = func.end_ea - func.start_ea

        # Decompilation — capped at _DECOMPILE_LINE_CAP lines.
        try:
            raw_code = decompile_function_safe(ea)
            code, total_lines = _cap_decompile(raw_code)
            result["decompiled"] = code
            if total_lines is not None:
                result["decompile_truncated"] = total_lines
        except Exception:
            result["decompiled"] = None

        # Assembly — opt-in only.
        if include_asm:
            try:
                result["assembly"] = get_assembly_lines(ea)
            except Exception:
                result["assembly"] = None

        # Strings — top 10 values only.
        result["strings"] = _compact_strings(extract_function_strings(ea))
        # Constants — top 10 non-trivial.
        result["constants"] = _filter_constants(extract_function_constants(ea))
        # Callees/callers — names only.
        result["callees"] = _compact_callees(get_callees(hex(ea)))
        result["callers"] = _compact_callees(get_callers(hex(ea)))
        result["xrefs"] = get_all_xrefs(ea)
        result["comments"] = get_all_comments(ea)
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
) -> dict:
    """Get a compact analysis of a single function: decompiled pseudocode (capped
    at 100 lines), top 10 strings as values, top 10 non-trivial constants, caller
    and callee names, cross-references, and basic block metrics. Disassembly is
    excluded by default to save context tokens — set include_asm=true only when
    you need raw instructions (crypto analysis, shellcode, decompiler failure).
    Use this instead of calling decompile, disasm, callees, xrefs_to, stack_frame,
    and basic_blocks separately."""

    try:
        ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"addr": addr, "error": str(exc)}

    return _analyze_function_internal(ea, include_asm=include_asm)


# ---------------------------------------------------------------------------
# Tool 2 — analyze_component
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(180.0)
def analyze_component(
    addrs: Annotated[list[str] | str, "Function addresses (comma-separated or list)"],
) -> dict:
    """Analyze a group of related functions as one logical unit. Returns a COMPACT
    summary of each function (name, prototype, size, callee names, top 5 strings,
    block count) plus relationship data: internal call graph, shared globals,
    interface vs internal classification, and strings used by multiple functions.
    Use analyze_function on individual addresses if you need full decompilation.
    Use this when you see a cluster of sub_* functions called from the same parent
    or when callees/callers overlap suggests a module."""

    import idaapi
    import idautils

    raw = normalize_list_input(addrs)
    if not raw:
        return {"error": "Empty address list"}

    ea_map: dict[int, str] = {}
    for a in raw:
        try:
            ea_map[_resolve_addr(a)] = a
        except IDAError:
            return {"error": f"Cannot resolve address: {a!r}"}

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
        name = idaapi.get_func_name(ea) or ""
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
                    "name": callee.get("name", ""),
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
        fname = idaapi.get_func_name(ea) or hex(ea)
        for g in gset:
            global_refcount[g].append(fname)

    shared_globals = []
    for g_ea, accessors in sorted(global_refcount.items()):
        if len(accessors) >= 2:
            shared_globals.append({
                "addr": hex(g_ea),
                "name": idaapi.get_name(g_ea) or hex(g_ea),
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
        fname = idaapi.get_func_name(ea) or hex(ea)
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
# Tool 3 — diff_before_after
# ---------------------------------------------------------------------------

_VALID_ACTIONS = frozenset({"rename_func", "set_type", "set_comment"})



@tool
@unsafe
@idasync
@tool_timeout(120.0)
def diff_before_after(
    addr: Annotated[str, "Function address"],
    action: Annotated[str, "Action: 'rename_func', 'set_type', 'set_comment'"],
    action_args: Annotated[dict, "Arguments for the action"],
) -> dict:
    """Preview a single change: applies it, captures the result, then restores the original state. The database is left unchanged."""

    import ida_nalt
    import ida_name
    import idaapi
    import ida_typeinf

    if action not in _VALID_ACTIONS:
        return {"error": f"Invalid action {action!r}. Must be one of: {', '.join(sorted(_VALID_ACTIONS))}"}

    try:
        ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"error": str(exc)}

    func = ida_funcs.get_func(ea)
    if func is None:
        return {"error": f"No function at {hex(ea)}"}

    # --- Before state ---
    before = decompile_function_safe(ea)
    old_name = idaapi.get_name(ea) or ""
    old_cmt = idaapi.get_cmt(ea, False) or ""
    old_tif = ida_typeinf.tinfo_t()
    had_type = bool(ida_nalt.get_tinfo(old_tif, ea))

    # --- Apply action ---
    applied: str
    try:
        if action == "rename_func":
            name = action_args.get("name")
            if not name:
                return {"error": "action_args must contain 'name'"}
            ok = idaapi.set_name(ea, name, idaapi.SN_CHECK)
            if not ok:
                return {"error": f"set_name failed for {name!r}"}
            applied = f"Renamed to {name!r}"

        elif action == "set_type":
            type_str = action_args.get("type")
            if not type_str:
                return {"error": "action_args must contain 'type'"}
            decl_str = type_str.strip()
            if not decl_str.endswith(";"):
                decl_str += ";"
            tif = ida_typeinf.tinfo_t()
            til = ida_typeinf.get_idati()
            parsed = ida_typeinf.parse_decl(tif, til, decl_str, ida_typeinf.PT_SIL)
            if parsed is None:
                return {"error": f"Failed to parse type: {type_str!r}"}
            ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
            if not ok:
                return {"error": f"apply_tinfo failed for {type_str!r}"}
            applied = f"Set type to {type_str!r}"

        elif action == "set_comment":
            comment = action_args.get("comment")
            if comment is None:
                return {"error": "action_args must contain 'comment'"}
            idaapi.set_cmt(ea, comment, False)
            applied = f"Set comment: {comment!r}"

        else:
            return {"error": f"Unhandled action {action!r}"}
    except Exception as exc:
        return {"error": f"Action {action!r} failed: {exc}"}

    # --- After ---
    after = decompile_function_safe(ea)

    # --- Restore original state ---
    restore_error = None
    try:
        ida_name.set_name(ea, old_name or "", ida_name.SN_CHECK | ida_name.SN_FORCE)
        idaapi.set_cmt(ea, old_cmt or "", False)
        if had_type:
            ida_typeinf.apply_tinfo(ea, old_tif, ida_typeinf.TINFO_DEFINITE)
        else:
            ida_nalt.del_tinfo(ea)
    except Exception as exc:
        restore_error = str(exc)

    reread = decompile_function_safe(ea)
    restored = restore_error is None and reread == before
    result: dict = {
        "before": before,
        "after": after,
        "action_applied": applied,
        "changes_detected": before != after,
        "restored": restored,
    }
    if not restored:
        result["restore_error"] = restore_error or "state differs after restore"
    return result


# ---------------------------------------------------------------------------
# Tool 4 — trace_data_flow
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
    """Follow cross-references from or to an address, automatically traversing
    multiple hops. Use 'forward' to see where data flows TO (xrefs-from), or
    'backward' to see where data flows FROM (xrefs-to). At each node in the
    traversal, returns the function name, instruction, and whether it's code or
    data. Use this when you find an interesting string, constant, or global and
    want to understand every code path that touches it without manually chaining
    xrefs_to calls. Do not use for call graph traversal — use callgraph for that.
    max_depth controls how many hops to follow (default 5, max 20)."""

    import idaapi
    import idautils
    import idc
    from collections import deque

    if direction not in ("forward", "backward", "both"):
        return {"error": f"direction must be 'forward', 'backward', or 'both', got {direction!r}"}

    try:
        start_ea = _resolve_addr(addr)
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
