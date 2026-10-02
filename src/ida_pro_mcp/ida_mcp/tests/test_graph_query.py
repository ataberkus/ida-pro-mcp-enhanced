"""graph_query call graph, path, field xref, and xref_type tests."""

from ..api_vnext import graph_query
from ..framework import skip_test, test
from ida_pro_mcp.vnext.contracts import VNextError


@test(binary="crackme03.elf")
def test_graph_callers_reaches_main_with_call_site():
    """callers(check_pw) finds main one hop up through the 0x12d3 call."""
    page = graph_query("callers", ["check_pw"], max_depth=2)["data"][0]
    depths = {node["name"]: node["depth"] for node in page["nodes"]}
    assert depths.get("main") == 1, page["nodes"]
    assert {"from": "0x123e", "to": "0x11a9", "site": "0x12d3", "type": "call"} in page["edges"], page["edges"]


@test(binary="crackme03.elf")
def test_graph_path_main_to_check_pw():
    """path [main, check_pw] is the single direct call at 0x12d3."""
    result = graph_query("path", ["main", "check_pw"])["data"]
    assert result["length"] == 1, result
    assert [node["name"] for node in result["paths"][0]] == ["main", "check_pw"], result
    assert result["paths"][0][1]["site"] == "0x12d3", result


@test(binary="crackme03.elf")
def test_graph_path_requires_two_targets():
    """path with one target is rejected rather than guessed."""
    try:
        graph_query("path", ["main"])
    except VNextError as exc:
        assert "exactly 2 targets" in str(exc)
    else:
        raise AssertionError("path accepted a single target")


@test(binary="crackme03.elf")
def test_graph_calls_pages_resume_without_duplicates():
    """calls(main) limit=2 pages through BFS nodes; the cursor resumes without repeats and reaches check_pw."""
    seen: list[str] = []
    cursor = None
    for _ in range(10):
        envelope = graph_query("calls", ["main"], limit=2, cursor=cursor)
        page = envelope["data"][0]
        assert len(page["nodes"]) <= 2, page
        seen.extend(node["addr"] for node in page["nodes"])
        cursor = envelope.get("next_cursor")
        if cursor is None:
            break
    assert len(seen) > 2, seen
    assert len(seen) == len(set(seen)), seen
    assert seen[0] == "0x123e" and "0x11a9" in seen, seen


@test(binary="crackme03.elf")
def test_graph_xrefs_honors_xref_type():
    """The success string at 0x201f has one data reference (0x12ea) and no code references."""
    data = graph_query("xrefs", ["0x201f"], options={"xref_type": "data"})["data"][0]
    assert [row["from"] for row in data["data"]] == ["0x12ea"], data
    code = graph_query("xrefs", ["0x201f"], options={"xref_type": "code"})["data"][0]
    assert code["data"] == [], code


@test(binary="crackme03.elf")
def test_graph_max_depth_warns_when_ignored():
    """A non-default max_depth on a kind without traversal depth produces a warning."""
    envelope = graph_query("xrefs", ["0x201f"], max_depth=5)
    assert envelope.get("warnings") == ["max_depth is ignored for kind=xrefs"], envelope
    assert "warnings" not in graph_query("calls", ["main"], max_depth=1)


@test(binary="crackme03.elf")
def test_graph_calls_unknown_root_is_per_target_error():
    """An unknown root yields an error row; the other root still returns its graph."""
    rows = graph_query("calls", ["definitely_not_a_symbol", "main"])["data"]
    assert "definitely_not_a_symbol" in rows[0]["error"], rows[0]
    assert rows[1]["addr"] == "0x123e", rows[1]


@test(binary="typed_fixture.elf")
def test_graph_field_xrefs_finds_point_y_in_sum_point():
    """field_xrefs Point.y finds the p->y read inside sum_point."""
    page = graph_query("field_xrefs", ["Point.y"])["data"][0]
    assert page.get("error") is None, page
    assert page["offset"] == "0x4", page
    hits = [row for row in page["xrefs"] if row["fn"]["name"] == "sum_point"]
    if not hits and page.get("warnings"):
        skip_test(f"decompiler field accesses unavailable: {page['warnings']}")
    assert hits, page
