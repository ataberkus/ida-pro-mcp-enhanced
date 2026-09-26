"""Pure analysis helpers shared by GUI and supervisor runtimes.

These functions must stay IDA-free so unit tests can lock matching and graph
bounding without loading IDAPython.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Any, Iterable

from .contracts import AnalysisGraph

_NODE_IDENTITY_FIELDS = ("id", "address", "addr", "name", "func")


def normalized_match_token(value: str) -> str:
    """Normalize an address or symbol so taint/dataflow matching is exact."""

    text = str(value).strip().lower()
    body = text[2:] if text.startswith("0x") else text
    try:
        if text.startswith("0x"):
            return hex(int(text, 16))
        if body and all(ch in "0123456789abcdef" for ch in body):
            if any(ch in "abcdef" for ch in body) or len(body) >= 6:
                return hex(int(body, 16))
        return hex(int(text, 0))
    except ValueError:
        return text


def node_match_values(node: dict[str, Any]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for key in _NODE_IDENTITY_FIELDS:
        raw = node.get(key)
        if raw is None or raw == "":
            continue
        token = normalized_match_token(str(raw))
        if token and token not in seen:
            seen.add(token)
            values.append(token)
    return values


def node_matches(node: dict[str, Any], tokens: Iterable[str]) -> bool:
    """Match a graph node on identity fields or whole instruction tokens.

    JSON-substring matching is intentionally avoided: tokens such as ``main``
    must not hit unrelated fields like ``remain`` or ``domain``.
    """

    wanted = {normalized_match_token(token) for token in tokens if token}
    if not wanted:
        return False
    identity = set(node_match_values(node))
    if identity & wanted:
        return True
    instruction = str(node.get("instruction") or "").lower()
    if not instruction:
        return False
    for token in wanted:
        if not token:
            continue
        if re.search(rf"(?<![0-9a-z_]){re.escape(token)}(?![0-9a-z_])", instruction):
            return True
    return False


def _node_address_int(node: dict[str, Any]) -> int | None:
    for key in ("address", "addr"):
        raw = node.get(key)
        if raw is None or raw == "":
            continue
        try:
            return int(str(raw), 0)
        except ValueError:
            continue
    return None


def nearest_node_id(nodes: list[dict[str, Any]], seed_ea: int) -> str | None:
    best_id: str | None = None
    best_dist: int | None = None
    for node in nodes:
        node_id = node.get("id")
        ea = _node_address_int(node)
        if node_id is None or ea is None:
            continue
        dist = abs(ea - seed_ea)
        if best_dist is None or dist < best_dist:
            best_dist = dist
            best_id = str(node_id)
    return best_id


def bounded_subgraph(
    graph: AnalysisGraph,
    seed_ea: int,
    direction: str,
    max_depth: int,
) -> AnalysisGraph:
    """Keep only nodes reachable from the seed within *max_depth* hops.

    A missing seed no longer returns the whole function graph. The nearest
    addressed node is used when the exact EA is absent from microcode.
    """

    seed_hex = hex(seed_ea)
    seed_ids = {
        str(node["id"])
        for node in graph.nodes
        if node.get("id") is not None and node.get("address") == seed_hex
    }
    if not seed_ids:
        nearest = nearest_node_id(graph.nodes, seed_ea)
        if nearest is None:
            graph.warnings.append(f"Seed {seed_hex} was not present in the analysis graph")
            graph.nodes = []
            graph.edges = []
            graph.evidence = []
            return graph
        graph.warnings.append(
            f"Seed {seed_hex} was not a graph node; using nearest node {nearest}"
        )
        seed_ids = {nearest}

    adjacency: dict[str, set[str]] = {}
    for edge in graph.edges:
        source, target = str(edge.get("source")), str(edge.get("target"))
        if direction in {"forward", "both"}:
            adjacency.setdefault(source, set()).add(target)
        if direction in {"backward", "both"}:
            adjacency.setdefault(target, set()).add(source)

    original_count = len(graph.nodes)
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

    graph.nodes = [node for node in graph.nodes if str(node.get("id")) in kept]
    graph.edges = [
        edge
        for edge in graph.edges
        if str(edge.get("source")) in kept and str(edge.get("target")) in kept
    ]
    graph.evidence = [
        item
        for item in graph.evidence
        if str(item.get("source")) in kept and str(item.get("target")) in kept
    ]
    if len(graph.nodes) < original_count:
        graph.truncated = True
    return graph


def normalize_reference_flow_graph(
    result: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Lift legacy xref traces onto the canonical id/address/source/target schema."""

    payload = result if isinstance(result, dict) else {}
    nodes: list[dict[str, Any]] = []
    for raw in payload.get("nodes", []) or []:
        if not isinstance(raw, dict):
            continue
        address = raw.get("address") or raw.get("addr")
        node_id = raw.get("id") or (str(address) if address else None)
        if node_id is None:
            continue
        node = dict(raw)
        node["id"] = str(node_id)
        if address:
            node["address"] = str(address)
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
        edge = dict(raw)
        edge["source"] = str(source)
        edge["target"] = str(target)
        edge["kind"] = kind
        edges.append(edge)

    truncated = bool(payload.get("truncated"))
    if payload.get("nodes") and len(nodes) >= 200:
        truncated = True
    if payload.get("edges") and len(edges) >= 500:
        truncated = True
    return nodes, edges, truncated
