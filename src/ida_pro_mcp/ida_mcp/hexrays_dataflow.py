"""Capability-gated Hex-Rays microcode def-use extraction.

The module imports IDA APIs lazily so importing ida-pro-mcp outside IDA remains
safe.  IDA access is kept inside ``idasync`` and only the resulting plain
Python graph crosses the runtime boundary.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from ida_pro_mcp.vnext.contracts import AnalysisEngine, AnalysisGraph, ErrorCode, VNextError

from .sync import IDAError, idasync
from .utils import parse_address


def _location_text(location: Any) -> str:
    try:
        return str(location.dstr())
    except Exception:
        return str(location)


def _has_common(left: Any, right: Any) -> bool:
    try:
        return bool(left.has_common(right))
    except Exception:
        return False


def _resolve_trace_address(addr: str | int) -> int:
    """Resolve a numeric address or IDA function/name to an effective address."""

    try:
        return parse_address(addr)
    except IDAError:
        import idaapi

        ea = idaapi.get_name_ea(idaapi.BADADDR, str(addr))
        if ea == idaapi.BADADDR:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"Address/name not found: {addr!r}")
        return int(ea)


def _predecessors(block: Any) -> list[int]:
    try:
        return [int(value) for value in block.predset]
    except TypeError:
        return []


def _instructions(block: Any, limit: int) -> list[Any]:
    result: list[Any] = []
    instruction = block.head
    seen: set[int] = set()
    while instruction is not None and len(result) < limit:
        identity = id(instruction)
        if identity in seen:
            break
        seen.add(identity)
        result.append(instruction)
        if instruction == block.tail:
            break
        instruction = instruction.next
    return result


def _bounded_subgraph(graph: AnalysisGraph, seed_ea: int, direction: str, max_depth: int) -> AnalysisGraph:
    seed_ids = {node["id"] for node in graph.nodes if node.get("address") == hex(seed_ea)}
    if not seed_ids:
        return graph

    adjacency: dict[str, set[str]] = {}
    for edge in graph.edges:
        source, target = edge["source"], edge["target"]
        if direction in {"forward", "both"}:
            adjacency.setdefault(source, set()).add(target)
        if direction in {"backward", "both"}:
            adjacency.setdefault(target, set()).add(source)

    kept = set(seed_ids)
    queue = deque((node_id, 0) for node_id in sorted(seed_ids))
    while queue:
        node_id, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for neighbor in sorted(adjacency.get(node_id, ())):
            if neighbor not in kept:
                kept.add(neighbor)
                queue.append((neighbor, depth + 1))
    graph.nodes = [node for node in graph.nodes if node["id"] in kept]
    graph.edges = [edge for edge in graph.edges if edge["source"] in kept and edge["target"] in kept]
    graph.evidence = [item for item in graph.evidence if item.get("source") in kept and item.get("target") in kept]
    return graph


@idasync
def trace_microcode(
    addr: str,
    *,
    direction: str = "forward",
    max_depth: int = 3,
    max_nodes: int = 2000,
) -> dict[str, Any]:
    """Build an intraprocedural reaching-definition graph from Hex-Rays microcode."""

    if direction not in {"forward", "backward", "both"}:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"Invalid data-flow direction: {direction}")
    if max_nodes < 1:
        raise VNextError(ErrorCode.LIMIT_EXCEEDED, "max_nodes must be positive")

    try:
        import ida_funcs
        import ida_hexrays
    except ImportError as exc:
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Hex-Rays APIs are not installed") from exc

    ea = _resolve_trace_address(addr)
    function = ida_funcs.get_func(ea)
    if function is None:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"Address is not inside a function: {addr}")

    try:
        failure = ida_hexrays.hexrays_failure_t()
        # IDA 9.x replaced mba_ranges_t with decomp_ranges_t for this API.
        # Retain the old overload only for older IDA versions.
        if hasattr(ida_hexrays, "decomp_ranges_t"):
            ranges = ida_hexrays.decomp_ranges_t(ea)
        else:
            ranges = ida_hexrays.mba_ranges_t(function)
        mba = ida_hexrays.gen_microcode(
            ranges,
            failure,
            None,
            getattr(ida_hexrays, "DECOMP_NO_WAIT", 0),
            ida_hexrays.MMAT_GLBOPT3,
        )
    except Exception as exc:
        raise VNextError(
            ErrorCode.NOT_SUPPORTED,
            "Hex-Rays microcode generation failed",
            details={"reason": str(exc)},
        ) from exc
    if mba is None:
        reason = getattr(failure, "desc", lambda: "decompiler unavailable")()
        raise VNextError(
            ErrorCode.NOT_SUPPORTED,
            "Hex-Rays microcode is unavailable for this function",
            details={"reason": str(reason)},
        )

    blocks: list[Any] = []
    instructions: list[tuple[int, int, Any, Any, Any]] = []
    block_instruction_ids: dict[int, list[int]] = {}
    truncated = False
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        blocks.append(block)
        block.make_lists_ready()
        ids: list[int] = []
        for ordinal, instruction in enumerate(_instructions(block, max_nodes + 1)):
            if len(instructions) >= max_nodes:
                truncated = True
                break
            definitions = block.build_def_list(instruction, ida_hexrays.MUST_ACCESS)
            if definitions.empty():
                definitions = block.build_def_list(instruction, ida_hexrays.MAY_ACCESS)
            uses = block.build_use_list(instruction, ida_hexrays.MAY_ACCESS)
            ids.append(len(instructions))
            instructions.append((serial, ordinal, instruction, definitions, uses))
        block_instruction_ids[serial] = ids
        if truncated:
            break

    nodes: list[dict[str, Any]] = []
    node_ids: list[str] = []
    for serial, ordinal, instruction, definitions, uses in instructions:
        instruction_ea = int(instruction.ea)
        address = None if instruction_ea < 0 else hex(instruction_ea)
        node_id = f"micro:{serial}:{ordinal}:{address or 'synthetic'}"
        node_ids.append(node_id)
        nodes.append(
            {
                "id": node_id,
                "address": address,
                "block": serial,
                "ordinal": ordinal,
                "instruction": str(instruction.dstr()),
                "definitions": _location_text(definitions),
                "uses": _location_text(uses),
            }
        )

    # Forward fixed-point analysis. Each state is a set of instruction indexes
    # whose definitions can reach the current program point.
    in_defs = {serial: set() for serial in block_instruction_ids}
    out_defs = {serial: set() for serial in block_instruction_ids}
    for _ in range(max(1, len(block_instruction_ids) * 4)):
        changed = False
        for serial, ids in block_instruction_ids.items():
            incoming: set[int] = set()
            if serial < len(blocks):
                for predecessor in _predecessors(blocks[serial]):
                    incoming.update(out_defs.get(predecessor, set()))
            current = set(incoming)
            for index in ids:
                definitions = instructions[index][3]
                if not definitions.empty():
                    current = {prior for prior in current if not _has_common(instructions[prior][3], definitions)}
                    current.add(index)
            if incoming != in_defs[serial] or current != out_defs[serial]:
                in_defs[serial] = incoming
                out_defs[serial] = current
                changed = True
        if not changed:
            break

    edges: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    edge_keys: set[tuple[int, int]] = set()
    for serial, ids in block_instruction_ids.items():
        current = set(in_defs[serial])
        for index in ids:
            definitions, uses = instructions[index][3], instructions[index][4]
            if not uses.empty():
                for prior in sorted(current):
                    if _has_common(instructions[prior][3], uses) and (prior, index) not in edge_keys:
                        edge_keys.add((prior, index))
                        edges.append(
                            {
                                "source": node_ids[prior],
                                "target": node_ids[index],
                                "kind": "def_use",
                                "confidence": 0.95,
                            }
                        )
                        evidence.append(
                            {
                                "source": node_ids[prior],
                                "target": node_ids[index],
                                "definition_locations": _location_text(instructions[prior][3]),
                                "use_locations": _location_text(uses),
                            }
                        )
            if not definitions.empty():
                current = {prior for prior in current if not _has_common(instructions[prior][3], definitions)}
                current.add(index)

    graph = AnalysisGraph(
        engine=AnalysisEngine.HEXRAYS_MICROCODE,
        fidelity="semantic_intraprocedural",
        nodes=nodes,
        edges=edges,
        evidence=evidence,
        unsupported_edges=[
            {"kind": "interprocedural_alias", "reason": "callee side effects require call-specific summaries"},
            {"kind": "concurrent_memory", "reason": "microcode reaching definitions are single-threaded"},
        ],
        warnings=["Direct def-use edges come from Hex-Rays microcode location lists."],
        truncated=truncated,
    )
    return _bounded_subgraph(graph, ea, direction, max(0, max_depth)).to_dict()
