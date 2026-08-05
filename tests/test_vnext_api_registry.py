from __future__ import annotations

import importlib.util
import pathlib
import sys
import threading
import types

import pytest

from _mcp_spec_support import call_rpc, load_ida_rpc_module
from ida_pro_mcp.vnext.contracts import VNextError
from ida_pro_mcp.vnext.policy import CANONICAL_TOOLS


def _load_vnext_api():
    rpc = load_ida_rpc_module()
    module_name = "_test_stub_ida_mcp.api_vnext"
    if module_name in sys.modules:
        return rpc, sys.modules[module_name]
    path = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp" / "api_vnext.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return rpc, module


def test_vnext_registry_is_bounded_and_annotated():
    rpc, _module = _load_vnext_api()
    tools = call_rpc(rpc.MCP_SERVER, "tools/list")["tools"]
    names = {tool["name"] for tool in tools}
    assert names <= CANONICAL_TOOLS
    assert len(names) <= 35
    assert {"server_capabilities", "analysis_run", "mutation_preview"} <= names
    for tool in tools:
        assert "annotations" in tool
        assert tool["_meta"]["ida_mcp"]["canonical"] is True


def test_vnext_prompts_and_resources_are_registered():
    rpc, _module = _load_vnext_api()
    prompts = call_rpc(rpc.MCP_SERVER, "prompts/list")["prompts"]
    assert {prompt["name"] for prompt in prompts} == {
        "triage_binary",
        "explain_function",
        "trace_input_to_sink",
        "deobfuscate_component",
        "compare_binaries",
        "review_patch",
        "generate_report",
    }
    resources = call_rpc(rpc.MCP_SERVER, "resources/list")["resources"]
    assert "ida://server/capabilities" in {resource["uri"] for resource in resources}
    templates = call_rpc(rpc.MCP_SERVER, "resources/templates/list")["resourceTemplates"]
    assert any("/jobs/{job_id}" in resource["uriTemplate"] for resource in templates)


def test_vnext_only_profile_hides_legacy_commit_debug_and_python_tools():
    rpc, _module = _load_vnext_api()
    def legacy_probe():
        return {"ok": True}

    rpc.tool(legacy_probe)
    try:
        rpc.configure_tool_policy(scopes={"read"}, legacy_tools=True)
        names = {tool["name"] for tool in call_rpc(rpc.MCP_SERVER, "tools/list")["tools"]}
        assert names <= CANONICAL_TOOLS
        assert "mutation_preview" in names
        assert "mutation_commit" not in names
        assert "debug_session" not in names
        assert "python_execute" not in names
        response = call_rpc(
            rpc.MCP_SERVER,
            "tools/call",
            name="legacy_probe",
            arguments={},
        )
        assert response["isError"] is True
        assert response["structuredContent"]["error"]["code"] == "PROFILE_DENIED"
    finally:
        rpc.MCP_SERVER.tools.methods.pop("legacy_probe", None)
        rpc.configure_tool_policy(scopes={"read"}, legacy_tools=False)


def test_vnext_internal_legacy_call_dispatches_preserved_method_map():
    rpc, api_vnext = _load_vnext_api()
    marker = object()
    previous = getattr(rpc.MCP_SERVER.tools, "_all_methods", marker)
    rpc.MCP_SERVER.tools._all_methods = {
        "legacy_probe": lambda value: {"value": value},
    }
    try:
        assert api_vnext._legacy_call("legacy_probe", {"value": 7}) == {"value": 7}
        with pytest.raises(VNextError, match="not registered"):
            api_vnext._legacy_call("missing_legacy_probe")
    finally:
        if previous is marker:
            del rpc.MCP_SERVER.tools._all_methods
        else:
            rpc.MCP_SERVER.tools._all_methods = previous


def test_memory_read_normalizes_string_byte_queries():
    _rpc, api_vnext = _load_vnext_api()
    assert api_vnext._normalize_memory_queries("bytes", ["0x401000"]) == [
        {"addr": "0x401000", "size": 16}
    ]
    assert api_vnext._normalize_memory_queries(
        "bytes", [{"addr": "0x401000", "size": 4}]
    ) == [{"addr": "0x401000", "size": 4}]
    assert api_vnext._normalize_memory_queries("string", ["0x401000"]) == ["0x401000"]
    with pytest.raises(VNextError, match=r"\{addr, ty\}"):
        api_vnext._normalize_memory_queries("integer", ["0x401000"])


def test_text_search_uses_and_returns_canonical_cursor(monkeypatch):
    _rpc, api_vnext = _load_vnext_api()
    calls = []

    def fake_legacy_call(name, arguments=None):
        calls.append((name, arguments))
        return {"n": 1, "hits": [], "cursor": {"next": "0x401010"}}

    monkeypatch.setattr(api_vnext, "_legacy_call", fake_legacy_call)
    incoming = api_vnext._encode_cursor(0x401000)
    result = api_vnext.search("text", ["needle"], 10, incoming)

    assert calls == [
        (
            "search_text",
            {
                "pattern": "needle",
                "limit": 10,
                "start": "0x401000",
                "end": "",
                "regex": False,
                "case_sensitive": False,
                "include": "all",
                "code_only": False,
            },
        )
    ]
    assert result["truncated"] is True
    assert result["next_cursor"] == api_vnext._encode_cursor(0x401010)


def test_mutation_aliases_reshape_set_name_and_rename_func():
    _rpc, api_vnext = _load_vnext_api()
    ops = api_vnext._parse_operations(
        [
            {
                "kind": "set_name",
                "arguments": {"addr": "0x401000", "name": "foo"},
            },
            {
                "kind": "rename_func",
                "arguments": {"addr": "0x402000", "name": "bar"},
            },
            {
                "kind": "rename",
                "arguments": {"func": [{"addr": "0x403000", "name": "baz"}]},
            },
        ]
    )
    assert [op.kind for op in ops] == ["rename", "rename", "rename"]
    assert ops[0].arguments == {"func": [{"addr": "0x401000", "name": "foo"}]}
    assert ops[1].arguments == {"func": [{"addr": "0x402000", "name": "bar"}]}
    assert ops[2].arguments == {"func": [{"addr": "0x403000", "name": "baz"}]}


def test_bridge_legacy_backends_are_defined_in_source():
    root = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"
    expected = {
        "api_core.py": "def search_text(",
        "api_debug.py": "def dbg_status(",
        "api_modify.py": ("def add_bookmark(", "def set_op_type(", "def make_data("),
        "api_python.py": "def py_exec_file(",
    }
    for filename, needles in expected.items():
        text = (root / filename).read_text(encoding="utf-8")
        if isinstance(needles, str):
            needles = (needles,)
        for needle in needles:
            assert needle in text, f"{filename} missing {needle}"


def test_sync_timeout_and_reentrancy_guards_remain_in_source():
    sync_path = (
        pathlib.Path(__file__).resolve().parents[1]
        / "src"
        / "ida_pro_mcp"
        / "ida_mcp"
        / "sync.py"
    )
    source = sync_path.read_text(encoding="utf-8")

    # Regression guards for upstream fixes accidentally overwritten by a
    # later integration: UI queue stalls and pure-C scans must never leave
    # HTTP workers blocked indefinitely.
    assert "res_container.put(" in source
    assert "call_stack.get_nowait()" in source
    assert "threading.Timer(timeout, _fire_native_cancel)" in source
    assert "ida_kernwin.set_cancelled()" in source
    assert "ida_kernwin.clr_cancelled()" in source
    assert "execute_ui_requests" in source
    assert "IDA_MCP_SYNC_QUEUE_TIMEOUT_SEC" in source
    assert "late_callback_skipped" in source
    assert "QTimer.singleShot(0, callback)" in source
    assert "ui_turn_released" in source


def _load_sync_module(
    monkeypatch,
    execute_ui_requests,
    *,
    is_main_thread=False,
    single_shot=None,
):
    load_ida_rpc_module()
    pkg_root = (
        pathlib.Path(__file__).resolve().parents[1]
        / "src"
        / "ida_pro_mcp"
        / "ida_mcp"
    )

    idaapi = types.ModuleType("idaapi")
    idaapi.get_kernel_version = lambda: "9.4"

    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.clr_cancelled = lambda: None
    ida_kernwin.set_cancelled = lambda: None
    ida_kernwin.execute_ui_requests = execute_ui_requests

    ida_pro = types.ModuleType("ida_pro")
    ida_pro.is_main_thread = lambda: is_main_thread

    batch_state = {"value": 0}
    idc = types.ModuleType("idc")

    def batch(value):
        previous = batch_state["value"]
        batch_state["value"] = value
        return previous

    idc.batch = batch
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setitem(sys.modules, "ida_kernwin", ida_kernwin)
    monkeypatch.setitem(sys.modules, "ida_pro", ida_pro)
    monkeypatch.setitem(sys.modules, "idc", idc)

    if single_shot is None:

        def single_shot(_delay, callback):
            callback()

    class QTimer:
        @staticmethod
        def singleShot(delay, callback):
            single_shot(delay, callback)

    pyside6 = types.ModuleType("PySide6")
    qtcore = types.ModuleType("PySide6.QtCore")
    qtcore.QTimer = QTimer
    pyside6.QtCore = qtcore
    monkeypatch.setitem(sys.modules, "PySide6", pyside6)
    monkeypatch.setitem(sys.modules, "PySide6.QtCore", qtcore)

    module_name = "_test_stub_ida_mcp.sync_queue_test"
    sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(module_name, pkg_root / "sync.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_sync_callback_runs_once_through_ui_queue(monkeypatch):
    callback_returns = []
    submitted_callbacks = []

    def execute_ui_requests(callbacks):
        submitted_callbacks.extend(callbacks)
        callback_returns.extend(callback() for callback in callbacks)
        return True

    sync = _load_sync_module(monkeypatch, execute_ui_requests)
    assert sync._sync_wrapper(lambda: "ok") == "ok"
    assert len(submitted_callbacks) == 1
    assert callback_returns == [False]


def test_sync_worker_result_waits_for_next_ui_turn(monkeypatch):
    timer_callbacks = []
    timer_scheduled = threading.Event()
    outcome = {}

    def execute_ui_requests(callbacks):
        assert [callback() for callback in callbacks] == [False]
        return True

    def single_shot(delay, callback):
        assert delay == 0
        timer_callbacks.append(callback)
        timer_scheduled.set()

    sync = _load_sync_module(
        monkeypatch, execute_ui_requests, single_shot=single_shot
    )

    def worker():
        try:
            outcome["result"] = sync._sync_wrapper(lambda: "ok")
        except BaseException as exc:
            outcome["error"] = exc

    worker_thread = threading.Thread(target=worker)
    worker_thread.start()
    assert timer_scheduled.wait(1.0)
    assert worker_thread.is_alive()

    timer_callbacks.pop(0)()
    worker_thread.join(1.0)
    assert not worker_thread.is_alive()
    assert outcome == {"result": "ok"}


def test_sync_callback_transports_tool_exception(monkeypatch):
    callback_returns = []

    def execute_ui_requests(callbacks):
        callback_returns.extend(callback() for callback in callbacks)
        return True

    def fail():
        raise ValueError("boom")

    sync = _load_sync_module(monkeypatch, execute_ui_requests)
    with pytest.raises(ValueError, match="boom"):
        sync._sync_wrapper(fail)
    assert callback_returns == [False]


def test_sync_queue_timeout_abandons_late_callback(monkeypatch):
    callbacks = []
    calls = []
    monkeypatch.setenv("IDA_MCP_SYNC_QUEUE_TIMEOUT_SEC", "0.01")

    def execute_ui_requests(items):
        callbacks.extend(items)
        return True

    def mutate():
        calls.append("called")

    sync = _load_sync_module(monkeypatch, execute_ui_requests)
    with pytest.raises(sync.IDASyncError, match=r"request 1.*diagnostics"):
        sync._sync_wrapper(mutate)

    assert calls == []
    assert len(callbacks) == 1
    assert callbacks[0]() is False
    assert calls == []


def test_sync_main_thread_bypasses_ui_queue(monkeypatch):
    def execute_ui_requests(_callbacks):
        raise AssertionError("main-thread calls must not be queued")

    sync = _load_sync_module(
        monkeypatch, execute_ui_requests, is_main_thread=True
    )
    assert sync._sync_wrapper(lambda: "direct") == "direct"
