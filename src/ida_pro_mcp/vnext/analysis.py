"""Pure data-flow and taint algorithms shared by GUI and supervisor runtimes.

These functions must stay IDA-free so unit tests can lock graph semantics
without loading IDAPython. IDA code lowers each function to a *flow* dict:

``func`` (int) / ``name`` (str)
``vars``    key -> {name, domain}; domain is register, stack, global or memory
``params``  variable keys of the parameters, in argument order
``nodes``   index 0 is the synthetic function entry (defines every parameter);
            each node: {address: int|None, line_no: int|None, line: str,
            defines: [key], uses: [key], calls: [{callee: int|None, args: [[key]]}],
            microcode: str}
``edges``   [source, target, key, "must"|"may"]: the definition of ``key`` at
            ``source`` reaches its use at ``target``
``line_of`` instruction ea -> pseudocode line index
"""

from __future__ import annotations

from collections import deque
from typing import Any, Callable, Iterable

Seed = tuple[int, "frozenset[str] | None", str]


def node_id(flow: dict[str, Any], index: int) -> str:
    if index == 0:
        return "entry"
    address = flow["nodes"][index]["address"]
    return hex(address) if address is not None else f"n{index}"


def _names(flow: dict[str, Any], keys: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(flow["vars"][key]["name"] for key in keys))


def render_node(flow: dict[str, Any], index: int, include_microcode: bool = False) -> dict[str, Any]:
    node = flow["nodes"][index]
    address = node["address"]
    rendered = {
        "id": node_id(flow, index),
        "address": hex(address) if address is not None else None,
        "line": node["line"],
        "defines": _names(flow, node["defines"]),
        "uses": _names(flow, node["uses"]),
    }
    if include_microcode:
        rendered["microcode"] = node["microcode"]
    return rendered


def variable_seeds(flow: dict[str, Any], keys: Iterable[str], direction: str) -> list[Seed]:
    """Seeds for one variable: its definitions forward, its uses backward.

    The first hop from a restricted seed only follows edges of that variable.
    A variable without definitions (used uninitialised) seeds its uses forward.
    """
    wanted = frozenset(keys)
    defs = [index for index, node in enumerate(flow["nodes"]) if wanted & set(node["defines"])]
    uses = [index for index, node in enumerate(flow["nodes"]) if wanted & set(node["uses"])]
    seeds: list[Seed] = []
    if direction in ("forward", "both"):
        seeds += [(index, wanted, "forward") for index in defs] or [(index, None, "forward") for index in uses]
    if direction in ("backward", "both"):
        seeds += [(index, wanted, "backward") for index in uses] + [(index, None, "backward") for index in defs]
    return seeds


def address_seeds(indexes: Iterable[int], direction: str) -> list[Seed]:
    directions = ("forward", "backward") if direction == "both" else (direction,)
    return [(index, None, way) for index in indexes for way in directions]


def _adjacency(flow: dict[str, Any], backward: bool) -> dict[int, list[tuple[int, int, str]]]:
    adjacency: dict[int, list[tuple[int, int, str]]] = {}
    for edge_index, (source, target, key, _kind) in enumerate(flow["edges"]):
        start, end = (target, source) if backward else (source, target)
        adjacency.setdefault(start, []).append((edge_index, end, key))
    return adjacency


def trace_graph(
    flow: dict[str, Any],
    seeds: list[Seed],
    max_depth: int,
    include_microcode: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Nodes/edges reachable from seeds within max_depth def-use hops."""
    kept_nodes: set[int] = {index for index, _restrict, _way in seeds}
    kept_edges: set[int] = set()
    truncated = False
    for way in ("forward", "backward"):
        adjacency = _adjacency(flow, backward=way == "backward")
        queue = deque((index, restrict, 0) for index, restrict, seed_way in seeds if seed_way == way)
        expanded: set[int] = set()
        while queue:
            index, restrict, depth = queue.popleft()
            if restrict is None:
                if index in expanded:
                    continue
                expanded.add(index)
            for edge_index, neighbor, key in adjacency.get(index, ()):
                if restrict is not None and key not in restrict:
                    continue
                if depth >= max_depth:
                    truncated = True
                    break
                kept_edges.add(edge_index)
                kept_nodes.add(neighbor)
                queue.append((neighbor, None, depth + 1))
    nodes = [render_node(flow, index, include_microcode) for index in sorted(kept_nodes)]
    edges = []
    for edge_index in sorted(kept_edges):
        source, target, key, kind = flow["edges"][edge_index]
        edges.append(
            {
                "source": node_id(flow, source),
                "target": node_id(flow, target),
                "variable": flow["vars"][key]["name"],
                "kind": kind,
            }
        )
    return nodes, edges, truncated


def taint_confidence(may_edges: int, hops: int, steps: int) -> float:
    """Heuristic path score: MAY edges, function hops, and long paths each lower it."""
    score = 0.95 * (0.75**may_edges) * (0.85**hops) * (0.98 ** max(0, steps - 2))
    return round(max(0.05, score), 2)


def _matches(spec: dict[str, Any], flow: dict[str, Any], node: dict[str, Any], tainted: Callable[[list[str]], bool]) -> bool:
    for ea in spec["addrs"]:
        if node["address"] == ea:
            return True
        line_no = flow["line_of"].get(ea)
        if line_no is not None and node["line_no"] == line_no:
            return True
    return any(
        call["callee"] in spec["callees"] and any(tainted(arg) for arg in call["args"])
        for call in node["calls"]
    )


def propagate_taint(
    load: Callable[[int], dict[str, Any] | None],
    seeds: list[dict[str, Any]],
    *,
    sinks: list[dict[str, Any]],
    sanitizers: list[dict[str, Any]],
    domains: set[str],
    max_hops: int,
    max_paths: int,
) -> dict[str, Any]:
    """Breadth-first taint over def-use edges, entering direct callees by parameter.

    ``seeds``: {source, func, node, var, out}; ``var`` is the tainted key arriving
    at the node (None = the whole node is tainted) and ``out`` restricts which of
    its definitions propagate (None = all). ``sinks``/``sanitizers``: {token,
    addrs, callees}; addresses match the node or its pseudocode statement,
    callees match a call whose argument carries the tainted value.
    """
    states: list[dict[str, Any]] = []
    visited: set[tuple] = set()
    queue: deque[int] = deque()

    def push(source: str, func: int, node: int, var: str | None, out: frozenset | None, hops: int, parent: int | None, may: int) -> None:
        key = (source, func, node, var, out)
        if key in visited:
            return
        visited.add(key)
        states.append({"source": source, "func": func, "node": node, "var": var, "out": out, "hops": hops, "parent": parent, "may": may})
        queue.append(len(states) - 1)

    for seed in seeds:
        out = seed.get("out")
        push(seed["source"], seed["func"], seed["node"], seed.get("var"), frozenset(out) if out is not None else None, 0, None, 0)

    hits: list[dict[str, Any]] = []
    hit_keys: set[tuple] = set()
    annotations: list[dict[str, Any]] = []
    truncated = False
    out_edges: dict[int, dict[int, list[tuple[int, int, str]]]] = {}

    def chain(state_index: int) -> list[dict[str, Any]]:
        result = []
        current: int | None = state_index
        while current is not None:
            result.append(states[current])
            current = states[current]["parent"]
        return result[::-1]

    def steps_of(path: list[dict[str, Any]]) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        for state in path:
            flow = load(state["func"])
            node = flow["nodes"][state["node"]]
            step = {
                "func": flow["name"],
                "address": hex(node["address"]) if node["address"] is not None else None,
                "line": node["line"],
            }
            if not steps or steps[-1] != step:
                steps.append(step)
        return steps

    while queue:
        if len(hits) >= max_paths:
            truncated = True
            break
        state_index = queue.popleft()
        state = states[state_index]
        flow = load(state["func"])
        if flow is None:
            continue
        node = flow["nodes"][state["node"]]
        var = state["var"]

        def tainted(arg: list[str]) -> bool:
            return var is None or var in arg

        stopped = [spec["token"] for spec in sanitizers if _matches(spec, flow, node, tainted)]
        if stopped:
            annotations.append(
                {
                    "source": state["source"],
                    "func": flow["name"],
                    "address": hex(node["address"]) if node["address"] is not None else None,
                    "line": node["line"],
                    "sanitizers": stopped,
                    "action": "propagation_stopped",
                }
            )
            continue
        for spec in sinks:
            hit_key = (state["source"], spec["token"], state["func"], state["node"])
            if hit_key in hit_keys or not _matches(spec, flow, node, tainted):
                continue
            hit_keys.add(hit_key)
            path = chain(state_index)
            steps = steps_of(path)
            path_domains = {flow_var["domain"] for item in path for flow_var in _state_vars(load, item)}
            hits.append(
                {
                    "source": state["source"],
                    "sink": spec["token"],
                    "steps": steps,
                    "hops": state["hops"],
                    "domains": sorted(path_domains),
                    "confidence": taint_confidence(state["may"], state["hops"], len(steps)),
                }
            )
            if len(hits) >= max_paths:
                break
        if state["hops"] < max_hops:
            for call in node["calls"]:
                if call["callee"] is None:
                    continue
                tainted_args = [position for position, arg in enumerate(call["args"]) if tainted(arg)]
                callee = load(call["callee"]) if tainted_args else None
                if callee is None:
                    continue
                for position in tainted_args:
                    if position < len(callee["params"]):
                        param = callee["params"][position]
                        if callee["vars"][param]["domain"] in domains:
                            push(state["source"], callee["func"], 0, None, frozenset({param}), state["hops"] + 1, state_index, state["may"])
        out = state["out"]
        if state["func"] not in out_edges:
            out_edges[state["func"]] = _adjacency(flow, backward=False)
        for edge_index, target, key in out_edges[state["func"]].get(state["node"], ()):
            if out is not None and key not in out:
                continue
            if flow["vars"][key]["domain"] not in domains:
                continue
            kind = flow["edges"][edge_index][3]
            push(state["source"], state["func"], target, key, None, state["hops"], state_index, state["may"] + (kind == "may"))
    return {"hits": hits, "sanitizer_annotations": annotations, "truncated": truncated, "warnings": []}


def _state_vars(load: Callable[[int], dict[str, Any] | None], state: dict[str, Any]) -> list[dict[str, str]]:
    flow = load(state["func"])
    keys = ([state["var"]] if state["var"] else []) + sorted(state["out"] or ())
    return [flow["vars"][key] for key in keys]


def normalize_reference_flow_graph(
    result: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Lift legacy xref traces onto the readable {id, address, line, defines, uses} node shape."""

    payload = result if isinstance(result, dict) else {}
    nodes: list[dict[str, Any]] = []
    for raw in payload.get("nodes", []) or []:
        if not isinstance(raw, dict):
            continue
        address = raw.get("address") or raw.get("addr")
        node_id_value = raw.get("id") or (str(address) if address else None)
        if node_id_value is None:
            continue
        node = {
            "id": str(node_id_value),
            "address": str(address) if address else None,
            "line": str(raw.get("instruction") or raw.get("name") or ""),
            "defines": [],
            "uses": [],
        }
        if raw.get("func"):
            node["func"] = str(raw["func"])
        nodes.append(node)

    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in payload.get("edges", []) or []:
        if not isinstance(raw, dict):
            continue
        source = raw.get("source") or raw.get("from")
        target = raw.get("target") or raw.get("to")
        if source is None or target is None:
            continue
        kind = str(raw.get("kind") or raw.get("type") or "xref")
        key = (str(source), str(target), kind)
        if key in seen:
            continue
        seen.add(key)
        edges.append({"source": str(source), "target": str(target), "kind": kind})

    truncated = bool(payload.get("truncated"))
    if payload.get("nodes") and len(nodes) >= 200:
        truncated = True
    if payload.get("edges") and len(edges) >= 500:
        truncated = True
    return nodes, edges, truncated
