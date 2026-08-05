from __future__ import annotations

import importlib.util
import pathlib
import queue
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
    api_core_source = sync_path.with_name("api_core.py").read_text(encoding="utf-8")

    # Regression guards for upstream fixes accidentally overwritten by a
    # later integration: UI queue stalls and pure-C scans must never leave
    # HTTP workers blocked indefinitely.
    assert "res_container.put(" in source
    assert "call_stack.pop()" in source
    assert "threading.Timer(timeout, _fire_native_cancel)" in source
    assert "ida_kernwin.set_cancelled()" in source
    assert "ida_kernwin.clr_cancelled()" in source
    assert "QCoreApplication.postEvent" in source
    assert "qt_post_event" in source
    assert "execute_ui_requests" not in source
    assert "IDA_MCP_SYNC_QUEUE_TIMEOUT_SEC" in source
    assert "late_callback_skipped" in source
    assert "QTimer.singleShot(0, callback)" in source
    assert "ui_turn_released" in source
    assert "ui_event_deferred" in source
    assert "nested_main_thread_call" in source
    assert "tool_reported_error" in source
    assert "ida_pro_enhanced_logs" in source
    assert "IDA_MCP_ERROR_LOG" in source
    assert "IDA_MCP_SEARCH_PAGE_BUDGET_SEC" in source
    assert "get_search_page_budget_seconds()" in api_core_source
    assert "heads_seen % 64" in api_core_source
    assert 'page_deadline_reason = "time_budget"' in api_core_source


def _load_sync_module(
    monkeypatch,
    *,
    is_main_thread=False,
    post_event=None,
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

    if post_event is None:

        def post_event(receiver, event):
            receiver.event(event)

    class QEvent:
        Type = int

        @staticmethod
        def registerEventType():
            return 1001

        def __init__(self, event_type):
            self._event_type = event_type

        def type(self):
            return self._event_type

    class QObject:
        def event(self, _event):
            return False

    class QCoreApplication:
        @staticmethod
        def postEvent(receiver, event):
            post_event(receiver, event)

    class QTimer:
        @staticmethod
        def singleShot(delay, callback):
            single_shot(delay, callback)

    pyside6 = types.ModuleType("PySide6")
    qtcore = types.ModuleType("PySide6.QtCore")
    qtcore.QCoreApplication = QCoreApplication
    qtcore.QEvent = QEvent
    qtcore.QObject = QObject
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


def test_sync_callback_runs_once_through_qt_event(monkeypatch):
    posted_events = []

    def post_event(receiver, event):
        posted_events.append(event)
        assert receiver.event(event) is True

    sync = _load_sync_module(monkeypatch, post_event=post_event)
    assert sync._sync_wrapper(lambda: "ok") == "ok"
    assert len(posted_events) == 1


def test_sync_immediately_chained_qt_events_are_not_lost(monkeypatch):
    posted_events = queue.Queue()
    outcome = {}

    def post_event(receiver, event):
        posted_events.put((receiver, event))

    sync = _load_sync_module(monkeypatch, post_event=post_event)

    def worker():
        try:
            outcome["results"] = [
                sync._sync_wrapper(lambda: "first"),
                sync._sync_wrapper(lambda: "second"),
            ]
        except BaseException as exc:
            outcome["error"] = exc

    worker_thread = threading.Thread(target=worker)
    worker_thread.start()
    for _ in range(2):
        receiver, event = posted_events.get(timeout=1.0)
        assert receiver.event(event) is True

    worker_thread.join(1.0)
    assert not worker_thread.is_alive()
    assert outcome == {"results": ["first", "second"]}


def test_sync_dispatcher_defers_recursive_qt_delivery(monkeypatch):
    posted_events = []
    order = []

    def post_event(receiver, event):
        posted_events.append((receiver, event))

    sync = _load_sync_module(monkeypatch, post_event=post_event)

    def second():
        order.append("second")

    def first():
        order.append("first-start")
        sync._post_to_main_thread(second)
        nested_receiver, nested_event = posted_events.pop(0)
        assert nested_receiver.event(nested_event) is True
        order.append("first-end")

    sync._post_to_main_thread(first)
    receiver, event = posted_events.pop(0)
    assert receiver.event(event) is True
    assert order == ["first-start", "first-end"]

    drain_receiver, drain_event = posted_events.pop(0)
    assert drain_receiver.event(drain_event) is True
    assert order == ["first-start", "first-end", "second"]
    assert posted_events == []


def test_sync_reports_structured_tool_errors(monkeypatch):
    sync = _load_sync_module(monkeypatch, is_main_thread=True)

    result = {
        "data": [
            {"addr": "0x401000", "code": None, "error": "Decompilation failed"},
            {"addr": "0x402000", "ok": False},
        ]
    }
    summary = sync._reported_error_summary(result)

    assert "$.data[0].error='Decompilation failed'" in summary
    assert "context={'addr': '0x401000'}" in summary
    assert "$.data[1].ok=False" in summary
    assert sync._result_outcome(result) == "reported_error"
    assert sync._result_outcome({"error": None}) == "ok"


def test_sync_allows_nested_calls_already_on_main_thread(monkeypatch):
    sync = _load_sync_module(monkeypatch, is_main_thread=True)

    def outer():
        return sync._sync_wrapper(lambda: "inner")

    assert sync._sync_wrapper(outer) == "inner"
    assert sync.call_stack == []


def test_sync_writes_reported_errors_to_dedicated_log(monkeypatch, tmp_path):
    sync_log = tmp_path / "sync.log"
    error_log = tmp_path / "errors.log"
    monkeypatch.setenv("IDA_MCP_SYNC_LOG", str(sync_log))
    monkeypatch.setenv("IDA_MCP_ERROR_LOG", str(error_log))
    sync = _load_sync_module(monkeypatch, is_main_thread=True)

    result = sync._sync_wrapper(lambda: {"error": "Decompilation failed"})

    assert result == {"error": "Decompilation failed"}
    assert "stage=tool_reported_error" in sync_log.read_text(encoding="utf-8")
    error_text = error_log.read_text(encoding="utf-8")
    assert "stage=tool_reported_error" in error_text
    assert "Decompilation failed" in error_text


def test_sync_worker_result_waits_for_next_ui_turn(monkeypatch):
    timer_callbacks = []
    timer_scheduled = threading.Event()
    outcome = {}

    def post_event(receiver, event):
        assert receiver.event(event) is True

    def single_shot(delay, callback):
        assert delay == 0
        timer_callbacks.append(callback)
        timer_scheduled.set()

    sync = _load_sync_module(
        monkeypatch, post_event=post_event, single_shot=single_shot
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
    def post_event(receiver, event):
        assert receiver.event(event) is True

    def fail():
        raise ValueError("boom")

    sync = _load_sync_module(monkeypatch, post_event=post_event)
    with pytest.raises(ValueError, match="boom"):
        sync._sync_wrapper(fail)


def test_sync_queue_timeout_abandons_late_callback(monkeypatch):
    posted_events = []
    calls = []
    monkeypatch.setenv("IDA_MCP_SYNC_QUEUE_TIMEOUT_SEC", "0.01")

    def post_event(receiver, event):
        posted_events.append((receiver, event))

    def mutate():
        calls.append("called")

    sync = _load_sync_module(monkeypatch, post_event=post_event)
    with pytest.raises(sync.IDASyncError, match=r"request 1.*diagnostics"):
        sync._sync_wrapper(mutate)

    assert calls == []
    assert len(posted_events) == 1
    receiver, event = posted_events[0]
    assert receiver.event(event) is True
    assert calls == []


def test_sync_main_thread_bypasses_ui_queue(monkeypatch):
    def post_event(_receiver, _event):
        raise AssertionError("main-thread calls must not be queued")

    sync = _load_sync_module(
        monkeypatch, is_main_thread=True, post_event=post_event
    )
    assert sync._sync_wrapper(lambda: "direct") == "direct"


def test_search_page_budget_config_is_bounded(monkeypatch):
    sync = _load_sync_module(monkeypatch, is_main_thread=True)

    monkeypatch.delenv("IDA_MCP_SEARCH_PAGE_BUDGET_SEC", raising=False)
    assert sync.get_search_page_budget_seconds() == 5.0
    monkeypatch.setenv("IDA_MCP_SEARCH_PAGE_BUDGET_SEC", "invalid")
    assert sync.get_search_page_budget_seconds() == 5.0
    monkeypatch.setenv("IDA_MCP_SEARCH_PAGE_BUDGET_SEC", "2.5")
    assert sync.get_search_page_budget_seconds() == 2.5
    monkeypatch.setenv("IDA_MCP_SEARCH_PAGE_BUDGET_SEC", "100")
    assert sync.get_search_page_budget_seconds() == 20.0
