"""dataflow_trace / taint_analyze on crackme03.

Fixture: main@0x123e passes argv[1] to strlen, check_pw@0x11a9 (call at 0x12da)
and printf (0x12f9, 0x1322); check_pw compares its first parameter at 0x1202.
"""

from ida_pro_mcp.vnext.contracts import ErrorCode, VNextError

from ..api_vnext import dataflow_trace, taint_analyze
from ..framework import skip_test, test


def _require_hexrays() -> None:
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        skip_test("Hex-Rays decompiler unavailable")


def _error(call) -> VNextError:
    try:
        call()
    except VNextError as exc:
        return exc
    raise AssertionError("expected a VNextError")


@test(binary="crackme03.elf")
def test_dataflow_trace_variable_seed_has_readable_nodes():
    """A variable seed reaches every argv use as pseudocode lines and variable names."""
    _require_hexrays()
    graph = dataflow_trace("main", variable="argv")
    assert graph["engine"] == "hexrays_microcode", graph
    lines = [node["line"] for node in graph["nodes"]]
    assert any("strlen" in line for line in lines), lines
    assert any("printf" in line for line in lines), lines
    assert not any("/*0x" in line for line in lines), lines
    assert all("microcode" not in node for node in graph["nodes"]), graph["nodes"]
    entry = next(node for node in graph["nodes"] if node["id"] == "entry")
    assert "argv" in entry["defines"], entry
    assert graph["edges"] and all(edge["variable"] == "argv" for edge in graph["edges"]), graph["edges"]
    users = [node for node in graph["nodes"] if node["id"] != "entry"]
    assert users and all("argv" in node["uses"] for node in users), users


@test(binary="crackme03.elf")
def test_dataflow_trace_func_var_form_and_microcode_toggle():
    """'main:argv' equals variable='argv'; include_microcode only adds the raw field."""
    _require_hexrays()
    plain = dataflow_trace("main", variable="argv")
    assert dataflow_trace("main:argv") == plain
    raw = dataflow_trace("main:argv", options={"include_microcode": True})
    assert all(isinstance(node.get("microcode"), str) and node["microcode"] for node in raw["nodes"]), raw["nodes"]
    stripped = [{k: v for k, v in node.items() if k != "microcode"} for node in raw["nodes"]]
    assert stripped == plain["nodes"]


@test(binary="crackme03.elf")
def test_dataflow_trace_unknown_variable_lists_names():
    _require_hexrays()
    exc = _error(lambda: dataflow_trace("main", variable="no_such_var"))
    assert exc.code is ErrorCode.INVALID_OPERATION, exc
    assert "argv" in str(exc) and "argc" in str(exc), str(exc)


@test(binary="crackme03.elf")
def test_taint_argv_reaches_printf_and_check_pw_call():
    """Readable steps end at the sink call; check_pw matches as a call receiving argv[1]."""
    _require_hexrays()
    result = taint_analyze(["main:argv"], ["printf", "check_pw"], max_depth=0)
    by_sink: dict[str, list] = {}
    for hit in result["hits"]:
        by_sink.setdefault(hit["sink"], []).append(hit)
    assert by_sink.get("printf"), result
    assert by_sink.get("check_pw"), result
    for hit in result["hits"]:
        assert hit["hops"] == 0, hit
        assert hit["steps"][0]["func"] == "main", hit
        assert "argv" in hit["steps"][0]["line"], hit
        assert 0 < hit["confidence"] <= 1, hit
    assert all("printf" in hit["steps"][-1]["line"] for hit in by_sink["printf"]), by_sink["printf"]
    assert "check_pw" in by_sink["check_pw"][0]["steps"][-1]["line"], by_sink["check_pw"]


@test(binary="crackme03.elf")
def test_taint_follows_argument_into_callee():
    """argv[1] enters check_pw's first parameter and reaches its compare at 0x1202 (one hop)."""
    _require_hexrays()
    result = taint_analyze(["main:argv"], ["0x1202"], max_depth=1)
    assert result["hits"], result
    hit = result["hits"][0]
    assert hit["hops"] == 1, hit
    assert hit["steps"][-1]["func"] == "check_pw" and hit["steps"][-1]["address"] == "0x1202", hit
    assert any(step["func"] == "main" for step in hit["steps"]), hit
    direct = taint_analyze(["main:argv"], ["printf"], max_depth=1)["hits"][0]
    assert hit["confidence"] < direct["confidence"], (hit, direct)
    # Boundaries: no hop budget, or a domain filter excluding argv's register, stops the flow.
    assert taint_analyze(["main:argv"], ["0x1202"], max_depth=0)["hits"] == []
    assert taint_analyze(["main:argv"], ["printf"], options={"domains": ["stack"]})["hits"] == []


@test(binary="crackme03.elf")
def test_taint_function_source_and_symbol_typos():
    """A function source seeds its parameters; misspelled symbols error with suggestions."""
    _require_hexrays()
    assert taint_analyze(["main"], ["printf"], max_depth=0)["hits"]
    exc = _error(lambda: taint_analyze(["chek_pw"], ["printf"]))
    assert exc.code is ErrorCode.INVALID_OPERATION, exc
    assert "did you mean" in str(exc) and "check_pw" in str(exc), str(exc)


@test(binary="crackme03.elf")
def test_taint_sanitizer_stops_propagation():
    """A sanitizer call receiving the value blocks the hop into it."""
    _require_hexrays()
    result = taint_analyze(["main:argv"], ["0x1202"], max_depth=1, sanitizers=["check_pw"])
    assert result["hits"] == [], result
    assert any("check_pw" in note["sanitizers"] for note in result["sanitizer_annotations"]), result
