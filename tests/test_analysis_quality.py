from __future__ import annotations

from ida_pro_mcp.vnext.analysis import (
    bounded_subgraph,
    merge_analysis_graphs,
    nearest_node_id,
    node_matches,
    normalize_reference_flow_graph,
    normalized_match_token,
)
from ida_pro_mcp.vnext.contracts import AnalysisEngine, AnalysisGraph


def _graph(**kwargs) -> AnalysisGraph:
    return AnalysisGraph(
        engine=AnalysisEngine.HEXRAYS_MICROCODE,
        fidelity="semantic_intraprocedural",
        **kwargs,
    )


def test_taint_tokens_do_not_match_json_substrings():
    node = {
        "id": "n1",
        "address": "0x401000",
        "name": "remain",
        "instruction": "mov eax, domain",
        "definitions": "remain.domain",
    }
    assert node_matches(node, {"main"}) is False
    assert node_matches(node, {"remain"}) is True
    assert node_matches(node, {"0x401000"}) is True
    assert node_matches(node, {"401000"}) is True
    assert node_matches(node, {"eax"}) is True
    assert normalized_match_token("0x401000") == normalized_match_token("401000")


def test_missing_taint_source_is_not_invented_by_helpers():
    nodes = [
        {"id": "a", "address": "0x401000", "name": "foo"},
        {"id": "b", "address": "0x401010", "name": "bar"},
    ]
    assert [node["id"] for node in nodes if node_matches(node, {"missing"})] == []
    assert nearest_node_id(nodes, 0x40100C) == "b"


def test_bounded_subgraph_does_not_dump_whole_graph_on_seed_miss():
    graph = _graph(
        nodes=[
            {"id": "a", "address": "0x401000"},
            {"id": "b", "address": "0x401010"},
            {"id": "c", "address": "0x401020"},
        ],
        edges=[
            {"source": "a", "target": "b", "kind": "def_use"},
            {"source": "b", "target": "c", "kind": "def_use"},
        ],
    )
    bounded = bounded_subgraph(graph, 0x401010, "forward", 1)
    assert {node["id"] for node in bounded.nodes} == {"b", "c"}
    assert bounded.truncated is True

    empty = _graph(
        nodes=[
            {"id": "a", "address": "0x401000"},
            {"id": "b", "address": "0x401010"},
            {"id": "c", "address": "0x401020"},
        ],
        edges=[{"source": "a", "target": "b", "kind": "def_use"}],
        warnings=[],
    )
    missed = bounded_subgraph(empty, 0x4010F0, "forward", 3)
    assert {node["id"] for node in missed.nodes} == {"c"}
    assert missed.warnings


def test_bounded_subgraph_both_keeps_predecessors_and_successors():
    graph = _graph(
        nodes=[
            {"id": "a", "address": "0x401000"},
            {"id": "b", "address": "0x401010"},
            {"id": "c", "address": "0x401020"},
        ],
        edges=[
            {"source": "a", "target": "b", "kind": "def_use"},
            {"source": "b", "target": "c", "kind": "def_use"},
        ],
    )
    bounded = bounded_subgraph(graph, 0x401010, "both", 1)
    assert {node["id"] for node in bounded.nodes} == {"a", "b", "c"}


def test_reference_flow_graph_normalizes_from_to_edges():
    nodes, edges, truncated = normalize_reference_flow_graph(
        {
            "nodes": [{"addr": "0x401000", "name": "buf", "instruction": "lea rax, buf"}],
            "edges": [{"from": "0x401000", "to": "0x401010", "type": "data"}],
            "truncated": False,
        }
    )
    assert nodes[0]["id"] == "0x401000"
    assert nodes[0]["address"] == "0x401000"
    assert edges[0]["source"] == "0x401000"
    assert edges[0]["target"] == "0x401010"
    assert edges[0]["kind"] == "data"
    assert truncated is False


def test_merge_analysis_graphs_deduplicates_edges():
    left = _graph(
        nodes=[{"id": "a", "address": "0x1"}],
        edges=[{"source": "a", "target": "b", "kind": "xref"}],
        warnings=["left"],
    )
    right = AnalysisGraph(
        engine=AnalysisEngine.REFERENCE_FLOW,
        fidelity="reference",
        nodes=[{"id": "b", "address": "0x2"}],
        edges=[{"source": "a", "target": "b", "kind": "xref"}],
        warnings=["right"],
        truncated=True,
    )
    merged = merge_analysis_graphs(left, right)
    assert {node["id"] for node in merged.nodes} == {"a", "b"}
    assert len(merged.edges) == 1
    assert merged.truncated is True
    assert merged.warnings == ["left", "right"]
