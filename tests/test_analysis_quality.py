from __future__ import annotations

from ida_pro_mcp.vnext.analysis import (
    address_seeds,
    normalize_reference_flow_graph,
    propagate_taint,
    trace_graph,
    variable_seeds,
)


def _node(address, line_no, line, defines=(), uses=(), calls=()):
    return {
        "address": address,
        "line_no": line_no,
        "line": line,
        "defines": list(defines),
        "uses": list(uses),
        "calls": list(calls),
        "microcode": f"insn@{address:#x}",
    }


# main(a): b = a; sink(b); callee(a); x = 0; use(x)
MAIN = {
    "func": 0x1000,
    "name": "main",
    "vars": {
        "a": {"name": "a", "domain": "register"},
        "b": {"name": "b", "domain": "stack"},
        "x": {"name": "x", "domain": "stack"},
    },
    "params": ["a"],
    "nodes": [
        _node(0x1000, 0, "void main(int a)", defines=["a"]),
        _node(0x1010, 1, "b = a;", defines=["b"], uses=["a"]),
        _node(0x1020, 2, "sink(b);", uses=["b"], calls=[{"callee": 0x9000, "args": [["b"]]}]),
        _node(0x1030, 3, "callee(a);", uses=["a"], calls=[{"callee": 0x2000, "args": [["a"]]}]),
        _node(0x1040, 4, "x = 0;", defines=["x"]),
        _node(0x1050, 5, "use(x);", uses=["x"]),
    ],
    "edges": [[0, 1, "a", "must"], [1, 2, "b", "may"], [0, 3, "a", "must"], [4, 5, "x", "must"]],
    "line_of": {0x1010: 1, 0x1020: 2, 0x1030: 3, 0x1040: 4, 0x1050: 5},
}
# callee(p): if (p)
CALLEE = {
    "func": 0x2000,
    "name": "callee",
    "vars": {"p": {"name": "p", "domain": "register"}},
    "params": ["p"],
    "nodes": [_node(0x2000, 0, "void callee(int p)", defines=["p"]), _node(0x2010, 1, "if ( p )", uses=["p"])],
    "edges": [[0, 1, "p", "must"]],
    "line_of": {0x2010: 1, 0x2014: 1},
}
FLOWS = {0x1000: MAIN, 0x2000: CALLEE}
ALL = {"register", "stack", "global", "memory"}


def _taint(sinks, *, sanitizers=(), domains=ALL, max_hops=1):
    seeds = [{"source": "main:a", "func": 0x1000, "node": 0, "var": None, "out": {"a"}}]
    return propagate_taint(
        FLOWS.get,
        seeds,
        sinks=sinks,
        sanitizers=list(sanitizers),
        domains=domains,
        max_hops=max_hops,
        max_paths=100,
    )


def _call(token, callee):
    return {"token": token, "addrs": set(), "callees": {callee}}


def _addr(token, ea):
    return {"token": token, "addrs": {ea}, "callees": set()}


def test_trace_graph_renders_readable_nodes_and_bounds_depth():
    nodes, edges, truncated = trace_graph(MAIN, address_seeds([0], "forward"), 3)
    assert [node["id"] for node in nodes] == ["entry", "0x1010", "0x1020", "0x1030"]
    assert nodes[1] == {"id": "0x1010", "address": "0x1010", "line": "b = a;", "defines": ["b"], "uses": ["a"]}
    assert {(e["source"], e["target"], e["variable"], e["kind"]) for e in edges} == {
        ("entry", "0x1010", "a", "must"),
        ("0x1010", "0x1020", "b", "may"),
        ("entry", "0x1030", "a", "must"),
    }
    assert truncated is False
    shallow, _edges, truncated = trace_graph(MAIN, address_seeds([0], "forward"), 1, include_microcode=True)
    assert [node["id"] for node in shallow] == ["entry", "0x1010", "0x1030"]
    assert truncated is True
    assert shallow[1]["microcode"] == "insn@0x1010"


def test_variable_seeds_restrict_first_hop_to_the_variable():
    nodes, _edges, _ = trace_graph(MAIN, variable_seeds(MAIN, ["x"], "forward"), 5)
    assert [node["id"] for node in nodes] == ["0x1040", "0x1050"]
    # Backward from b's use: b's definition, then what flowed into it.
    nodes, _edges, _ = trace_graph(MAIN, variable_seeds(MAIN, ["b"], "backward"), 5)
    assert [node["id"] for node in nodes] == ["entry", "0x1010", "0x1020"]


def test_taint_hits_call_sinks_and_enters_callees_by_parameter():
    result = _taint([_call("sink", 0x9000), _addr("0x2014", 0x2014)])
    hits = {hit["sink"]: hit for hit in result["hits"]}
    assert [step["line"] for step in hits["sink"]["steps"]] == ["void main(int a)", "b = a;", "sink(b);"]
    assert hits["sink"]["hops"] == 0
    assert hits["sink"]["domains"] == ["register", "stack"]
    # Address sinks match the statement containing them (0x2014 is inside "if ( p )").
    callee_hit = hits["0x2014"]
    assert callee_hit["hops"] == 1
    assert [step["func"] for step in callee_hit["steps"]] == ["main", "main", "callee", "callee"]
    # The direct must-path scores higher than the hop path and the may-edge path.
    direct = _taint([_call("callee", 0x2000)])["hits"][0]
    assert direct["confidence"] > callee_hit["confidence"]
    assert direct["confidence"] > hits["sink"]["confidence"]


def test_taint_bounds_hops_domains_and_sanitizers():
    assert _taint([_addr("p", 0x2010)], max_hops=0)["hits"] == []
    assert _taint([_call("sink", 0x9000)], domains={"register"})["hits"] == []
    stopped = _taint([_call("sink", 0x9000)], sanitizers=[_addr("b = a", 0x1010)])
    assert stopped["hits"] == []
    assert stopped["sanitizer_annotations"][0]["line"] == "b = a;"


def test_reference_flow_graph_uses_readable_node_shape():
    nodes, edges, truncated = normalize_reference_flow_graph(
        {
            "nodes": [{"addr": "0x401000", "name": "buf", "instruction": "lea rax, buf", "func": "main", "depth": 0}],
            "edges": [{"from": "0x401000", "to": "0x401010", "type": "data"}],
            "truncated": False,
        }
    )
    assert nodes == [{"id": "0x401000", "address": "0x401000", "line": "lea rax, buf", "defines": [], "uses": [], "func": "main"}]
    assert edges == [{"source": "0x401000", "target": "0x401010", "kind": "data"}]
    assert truncated is False
