"""idalib supervisor tests that do not require IDA/idalib."""

import os
import sys
import threading
import time
from pathlib import Path

import pytest

from ida_pro_mcp import idalib_supervisor as supmod


class _FakeProcess:
    pid = 12345
    returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class _DeadProcess(_FakeProcess):
    returncode = 1


class _FakeSupervisor(supmod.IdalibSupervisor):
    def __init__(self):
        super().__init__(supmod.McpServer("test"), max_workers=4)
        self.forwarded: list[dict] = []
        self.opened: list[tuple[str, dict]] = []
        self.tool_calls: list[tuple[str, dict | None]] = []

    def _spawn_worker(self):
        return supmod.WorkerSession(
            session_id="__schema__",
            input_path="",
            filename="",
            host="127.0.0.1",
            port=1,
            process=_FakeProcess(),
            auth_token="ephemeral-secret",
        )

    def _worker_rpc(self, worker, payload, *, timeout=None):
        method = payload.get("method")
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {
                    "tools": [
                        {
                            "name": "decompile",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"addr": {"type": "string"}},
                                "required": ["addr"],
                            },
                        },
                        {"name": "idb_open", "inputSchema": {"type": "object"}},
                    ]
                },
            }
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resources": []}}
        if method == "resources/templates/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resourceTemplates": []}}
        self.forwarded.append(payload)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"ok": True}}

    def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
        self.tool_calls.append((name, arguments))
        if name == "idb_open":
            assert arguments is not None
            self.opened.append((name, arguments))
            warmup = None
            if arguments.get("build_caches") or arguments.get("init_hexrays"):
                warmup = {"ok": True, "steps": [], "health": {"status": "ok"}}
            return {
                "success": True,
                "session": {
                    "session_id": arguments["preferred_session_id"],
                    "input_path": arguments["input_path"],
                    "filename": Path(arguments["input_path"]).name,
                    "created_at": "now",
                    "last_accessed": "now",
                    "is_analyzing": False,
                    "metadata": {},
                },
                "warmup": warmup,
            }
        return {"ok": True, "error": None}

    def _session_is_reachable(self, session):
        return session.is_alive()

    def _probe_session_health(self, session):
        reachable = self._session_is_reachable(session)
        return {
            "backend": session.backend,
            "process_alive": session.is_alive(),
            "tcp_connect": reachable if session.backend == "worker" else None,
            "rpc_ping": reachable if session.backend == "worker" else None,
            "reachable": reachable,
            "failed_probe": None if reachable else "tcp_connect",
            "error": None if reachable else "unreachable",
        }


def _patch_discovery(*, instances, probe):
    old_discover = supmod._discovery.discover_instances
    old_probe = supmod._discovery.probe_instance
    supmod._discovery.discover_instances = lambda: instances
    supmod._discovery.probe_instance = lambda *_args, **_kwargs: probe

    def restore():
        supmod._discovery.discover_instances = old_discover
        supmod._discovery.probe_instance = old_probe

    return restore


def test_supervisor_import_does_not_import_ida_modules():
    assert "idapro" not in sys.modules
    assert "idaapi" not in sys.modules


def test_worker_rpc_default_has_no_socket_timeout(monkeypatch):
    class _FakeResponse:
        status = 200
        reason = "OK"

        def read(self):
            return b'{"jsonrpc":"2.0","result":{"ok":true},"id":1}'

    class _FakeConnection:
        instances = []

        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port
            self.timeout = timeout
            type(self).instances.append(self)

        def request(self, method, path, body, headers):
            pass

        def getresponse(self):
            return _FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(supmod.http.client, "HTTPConnection", _FakeConnection)
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="",
        filename="",
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    sup._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    sup._worker_rpc(worker, {"jsonrpc": "2.0", "id": 2, "method": "ping"}, timeout=2.0)

    assert _FakeConnection.instances[0].timeout is None
    assert _FakeConnection.instances[1].timeout == 2.0


def test_worker_rpc_uses_ephemeral_bearer_credential(monkeypatch):
    captured = {}

    class _FakeResponse:
        status = 200
        reason = "OK"

        def read(self):
            return b'{"jsonrpc":"2.0","result":{},"id":1}'

    class _FakeConnection:
        def __init__(self, host, port, timeout=None):
            pass

        def request(self, method, path, body, headers):
            captured.update(headers)

        def getresponse(self):
            return _FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(supmod.http.client, "HTTPConnection", _FakeConnection)
    supervisor = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="",
        filename="",
        port=12345,
        process=_FakeProcess(),
        auth_token="ephemeral-secret",
    )
    supervisor._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert captured["Authorization"] == "Bearer ephemeral-secret"


def test_binary_diff_matcher_uses_symbols_signatures_and_instruction_hashes():
    left = [
        {"addr": "0x1000", "name": "parse", "size": "0x20", "signature": "AA ? BB", "instruction_hash": "h1"},
        {"addr": "0x2000", "name": "sub_2000", "size": "0x10", "signature": "CC DD", "instruction_hash": "h2"},
        {"addr": "0x3000", "name": "removed", "size": "0x8"},
    ]
    right = [
        {"addr": "0x5000", "name": "parse", "size": "0x24", "signature": "AA ? BB", "instruction_hash": "changed"},
        {"addr": "0x6000", "name": "sub_6000", "size": "0x10", "signature": "CC DD", "instruction_hash": "h2"},
        {"addr": "0x7000", "name": "added", "size": "0x8"},
    ]
    matches, removed, added = supmod.IdalibSupervisor._match_functions(left, right)
    assert len(matches) == 2
    assert any(item["left"]["name"] == "parse" and item["changed"] for item in matches)
    assert removed[0]["name"] == "removed"
    assert added[0]["name"] == "added"


def test_cleanup_partial_database_removes_only_new_parts(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    existing = Path(str(sample) + ".id0")
    existing.write_bytes(b"existing database state")
    packed = Path(str(sample) + ".i64")
    packed.write_bytes(b"packed database")

    preserved = supmod.IdalibSupervisor._existing_partial_database_parts(str(sample))
    new_id1 = Path(str(sample) + ".id1")
    new_id1.write_bytes(b"incomplete")
    new_nam = Path(str(sample) + ".nam")
    new_nam.write_bytes(b"incomplete")

    supmod.IdalibSupervisor._cleanup_partial_database(
        str(sample),
        preserve=preserved,
    )

    assert existing.read_bytes() == b"existing database state"
    assert not new_id1.exists()
    assert not new_nam.exists()
    assert packed.read_bytes() == b"packed database"


def test_open_session_cleans_new_parts_after_worker_failure(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    existing = Path(str(sample) + ".id0")
    existing.write_bytes(b"existing database state")
    packed = Path(str(sample) + ".i64")
    packed.write_bytes(b"packed database")

    class _FailingSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            assert arguments is not None
            Path(arguments["input_path"] + ".id1").write_bytes(b"incomplete")
            raise ConnectionResetError(10054, "worker reset")

    sup = _FailingSupervisor()
    with pytest.raises(ConnectionResetError):
        sup.open_session(
            str(sample),
            mode="force_headless",
            run_auto_analysis=False,
            build_caches=False,
            init_hexrays=False,
        )

    assert existing.read_bytes() == b"existing database state"
    assert not Path(str(sample) + ".id1").exists()
    assert packed.read_bytes() == b"packed database"


def test_failed_gui_fallback_cleans_new_parts_after_worker_failure(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    existing = Path(str(sample) + ".id0")
    existing.write_bytes(b"existing database state")

    class _FailingSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            assert arguments is not None
            Path(arguments["input_path"] + ".id1").write_bytes(b"incomplete")
            raise ConnectionResetError(10054, "worker reset")

    gui_session = supmod.WorkerSession(
        session_id="gui",
        input_path=str(sample),
        filename=sample.name,
        backend="gui",
        owned=False,
    )
    sup = _FailingSupervisor()
    with pytest.raises(ConnectionResetError):
        sup._reopen_gui_session_headless(gui_session)

    assert existing.read_bytes() == b"existing database state"
    assert not Path(str(sample) + ".id1").exists()


def test_worker_tools_inject_optional_database_and_filter_management_tools():
    sup = _FakeSupervisor()
    tools = sup.worker_tools()
    names = [tool["name"] for tool in tools]
    assert names == ["decompile"]
    schema = tools[0]["inputSchema"]
    assert "database" in schema["properties"]
    assert schema["required"] == ["addr"]


def test_inject_database_arg_drops_worker_required_database():
    sup = _FakeSupervisor()
    injected = sup._inject_database_arg(
        {
            "name": "decompile",
            "inputSchema": {
                "type": "object",
                "properties": {"addr": {"type": "string"}},
                "required": ["addr", "database"],
            },
        }
    )
    assert injected["inputSchema"]["required"] == ["addr"]


def _analysis_run_schema():
    return {
        "name": "analysis_run",
        "description": "Run analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {"type": "string", "enum": ["triage", "function"]},
                "options": {
                    "anyOf": [
                        {
                            "type": "object",
                            "properties": {"max_functions": {"type": "integer"}},
                            "required": [],
                            "additionalProperties": False,
                        },
                        {"type": "null"},
                    ]
                },
            },
            "required": ["mode"],
        },
    }


def test_tools_list_advertises_supervisor_binary_diff_once(monkeypatch):
    sup = _FakeSupervisor()
    original_rpc = sup._worker_rpc

    def worker_rpc(worker, payload, *, timeout=None):
        response = original_rpc(worker, payload, timeout=timeout)
        if payload.get("method") == "tools/list":
            response["result"]["tools"].append(_analysis_run_schema())
        return response

    sup._worker_rpc = worker_rpc
    monkeypatch.setattr(supmod, "supervisor", sup)
    for _ in range(2):  # second call is served from the cache
        tools = supmod._handle_tools_list({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
        names = [tool["name"] for tool in tools]
        assert len(names) == len(set(names))
        assert {"idb_open", "idb_list", "idb_close"} <= set(names)
        analysis = next(tool for tool in tools if tool["name"] == "analysis_run")
        props = analysis["inputSchema"]["properties"]
        assert props["mode"]["enum"] == ["triage", "function", "binary_diff"]
        assert "right_database" in props["options"]["anyOf"][0]["properties"]
        assert analysis["description"].count("binary_diff (supervisor)") == 1
        assert "database" not in analysis["inputSchema"]["required"]


def test_handle_tools_call_defaults_to_only_database(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")
    monkeypatch.setattr(supmod, "supervisor", sup)
    result = supmod._handle_tools_call(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "decompile", "arguments": {"addr": "0x1000", "database": ""}},
        }
    )
    assert result["result"] == {"ok": True}
    assert sup.forwarded[-1]["params"]["arguments"] == {"addr": "0x1000"}


def test_handle_tools_call_without_database_errors_when_none_open(monkeypatch):
    monkeypatch.setattr(supmod, "supervisor", _FakeSupervisor())
    result = supmod._handle_tools_call(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "decompile", "arguments": {"addr": "0x1000"}},
        }
    )
    assert result["result"]["isError"] is True
    assert "No database is open" in result["result"]["content"][0]["text"]
    assert "idb_open" in result["result"]["content"][0]["text"]
    assert not supmod.supervisor.forwarded


def test_open_session_rejects_unknown_mode(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    try:
        sup.open_session(str(sample), session_id="sample", mode="bogus")
    except ValueError as e:
        assert "Unknown mode" in str(e)
    else:
        raise AssertionError("expected ValueError for unknown mode")


def test_open_session_prefer_headless_skips_gui_discovery(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="sample", mode="prefer_headless")
        assert session.backend == "worker"
        assert sup.opened, "expected the worker to be invoked despite a running GUI"
    finally:
        restore()


def test_open_session_force_headless_ignores_running_gui(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="sample", mode="force_headless")
        assert session.backend == "worker"
    finally:
        restore()


def test_open_session_force_gui_launches_when_no_gui_found(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    calls = []

    def fake_launch(file_path, **kwargs):
        calls.append(file_path)
        return {
            "success": True,
            "host": "127.0.0.1",
            "port": 31337,
            "pid": 4242,
            "binary": "sample.bin",
        }

    monkeypatch.setattr(supmod._discovery, "launch_gui_instance", fake_launch)
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="force_gui")
        assert session.backend == "gui"
        assert session.port == 31337
        assert calls == [str(sample.resolve())] or calls == [str(sample)]
    finally:
        restore()


def test_idb_list_includes_unadopted_gui_instances(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")

    extra_idb = tmp_path / "other.bin.i64"
    extra_idb.write_bytes(b"idb")
    monkeypatch.setattr(
        supmod._discovery,
        "discover_instances",
        lambda: [
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 1234,
                "binary": "other.bin",
                "idb_path": str(extra_idb),
                "started_at": "now",
            }
        ],
    )
    monkeypatch.setattr(supmod._discovery, "probe_instance", lambda *_args, **_kwargs: True)

    listed = sup.list_sessions()
    by_id = {entry["session_id"]: entry for entry in listed}
    assert "sample" in by_id and by_id["sample"]["adopted"] is True
    unadopted = [entry for entry in listed if not entry["adopted"]]
    assert len(unadopted) == 1
    assert unadopted[0]["backend"] == "gui"
    assert unadopted[0]["input_path"] == str(extra_idb)
    assert unadopted[0]["pid"] == 1234


def test_idb_list_reports_unadopted_worker_instances_as_workers(tmp_path, monkeypatch):
    extra_idb = tmp_path / "worker.bin"
    extra_idb.write_bytes(b"idb")
    monkeypatch.setattr(
        supmod._discovery,
        "discover_instances",
        lambda: [
            {
                "host": "127.0.0.1",
                "port": 31338,
                "pid": 4321,
                "binary": "worker.bin",
                "idb_path": str(extra_idb),
                "started_at": "now",
                "backend": "worker",
            }
        ],
    )
    monkeypatch.setattr(supmod._discovery, "probe_instance", lambda *_args, **_kwargs: True)

    listed = _FakeSupervisor().list_sessions()

    assert len(listed) == 1
    assert listed[0]["backend"] == "worker"
    assert listed[0]["metadata"]["backend"] == "worker"
    assert listed[0]["worker_pid"] == 4321
    assert listed[0]["adopted"] is False


def test_prefer_headless_adopts_only_registered_worker_backend(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="sample", mode="prefer_headless")
        assert session.backend == "worker"
        assert session.owned is True
        assert sup.opened, "legacy GUI registration should not be adopted as a worker"
    finally:
        restore()


def test_idb_list_omits_unadopted_when_already_adopted(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    idb = tmp_path / "sample.bin.i64"
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 1234,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        monkeypatch.setattr(supmod._discovery, "probe_instance", lambda *_args, **_kwargs: True)
        listed = sup.list_sessions()
        assert all(entry["adopted"] for entry in listed)
        assert len(listed) == 1
    finally:
        restore()


def test_open_session_forwards_warmup_flags_and_captures_result(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(
        str(sample),
        session_id="sample",
        run_auto_analysis=False,
        build_caches=True,
        init_hexrays=True,
    )
    args = sup.opened[0][1]
    assert args["build_caches"] is True
    assert args["init_hexrays"] is True
    assert args["run_auto_analysis"] is False
    assert session.last_warmup is not None
    assert session.last_warmup["ok"] is True
    assert session.auth_token == "ephemeral-secret"


def test_open_session_forwards_idle_ttl_sec(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample", idle_ttl_sec=1800)
    args = sup.opened[0][1]
    assert args["idle_ttl_sec"] == 1800


def test_open_session_defaults_idle_ttl_sec_to_baseline(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")
    args = sup.opened[0][1]
    assert args["idle_ttl_sec"] == 600


def test_open_session_skips_warmup_when_flags_disabled(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(
        str(sample),
        session_id="sample",
        build_caches=False,
        init_hexrays=False,
    )
    args = sup.opened[0][1]
    assert args["build_caches"] is False
    assert args["init_hexrays"] is False
    assert session.last_warmup is None


def test_resolve_session_defaults_only_when_unambiguous(tmp_path):
    sup = _FakeSupervisor()
    with pytest.raises(RuntimeError, match="No database is open"):
        sup.resolve_session(None)

    first = tmp_path / "first.bin"
    first.write_bytes(b"1")
    sup.open_session(str(first), session_id="first")
    assert sup.resolve_session(None).session_id == "first"
    assert sup.resolve_session("").session_id == "first"

    second = tmp_path / "second.bin"
    second.write_bytes(b"2")
    sup.open_session(str(second), session_id="second")
    with pytest.raises(RuntimeError) as excinfo:
        sup.resolve_session(None)
    message = str(excinfo.value)
    assert "2 databases are open" in message
    assert '"filename": "first.bin"' in message and '"session_id": "second"' in message


def test_tool_error_result_omits_structured_content():
    result = supmod._call_tool_result({"error": "no database"}, is_error=True)
    assert result["isError"] is True
    assert "structuredContent" not in result


def test_open_session_reuses_schema_worker(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.worker_tools()  # creates the idle/schema worker
    session = sup.open_session(str(sample), session_id="sample")
    assert session.session_id == "sample"
    assert sup.opened[0][1]["preferred_session_id"] == "sample"



def test_session_resource_forwards_worker_local_active_uri(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")
    old_supervisor = supmod.supervisor
    supmod.supervisor = sup
    try:
        response = supmod._handle_resources_read(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "resources/read",
                "params": {"uri": "ida://sessions/sample/metadata"},
            }
        )
    finally:
        supmod.supervisor = old_supervisor

    assert response["result"] == {"ok": True}
    assert sup.forwarded[-1]["params"]["uri"] == "ida://sessions/active/metadata"


def test_protocol_cancellation_routes_to_tracked_worker(monkeypatch):
    sup = _FakeSupervisor()
    worker = sup._spawn_worker()
    sup._track_worker_request("transport-1", 41, worker)
    old_supervisor = supmod.supervisor
    supmod.supervisor = sup
    monkeypatch.setattr(
        supmod.mcp,
        "get_current_transport_session_id",
        lambda: "transport-1",
    )
    try:
        result = supmod.dispatch_supervisor(
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 41, "reason": "test"},
            }
        )
    finally:
        supmod.supervisor = old_supervisor

    assert result is None
    assert sup.forwarded[-1]["method"] == "notifications/cancelled"
    assert sup.forwarded[-1]["params"]["requestId"] == 41


def test_resolve_session_accepts_filename_basename_path_and_id_prefix(tmp_path):
    sample = tmp_path / "crackme03.elf"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="0123456789abcdef")
    other = tmp_path / "other.bin"
    other.write_bytes(b"y")
    sup.open_session(str(other), session_id="0123ffffffffffff")

    selectors = ["crackme03.elf", "crackme03", str(sample), str(sample) + ".i64", "0123456"]
    if os.name == "nt":
        selectors.append("CRACKME03.ELF")
    for selector in selectors:
        assert sup.resolve_session(selector).session_id == "0123456789abcdef", selector
    with pytest.raises(RuntimeError, match="Session not found: 01234"):
        sup.resolve_session("01234")  # shared 5-char prefix is below the alias minimum


def test_resolve_session_rejects_ambiguous_and_short_selectors(tmp_path):
    left = tmp_path / "a" / "app.exe"
    right = tmp_path / "b" / "app.exe"
    left.parent.mkdir()
    right.parent.mkdir()
    left.write_bytes(b"1")
    right.write_bytes(b"2")
    sup = _FakeSupervisor()
    sup.open_session(str(left), session_id="aaaaaaaa1")
    sup.open_session(str(right), session_id="aaaaaaaa2")

    for selector in ("app.exe", "app", "aaaaaaaa"):
        with pytest.raises(RuntimeError) as excinfo:
            sup.resolve_session(selector)
        assert "ambiguous" in str(excinfo.value)
        assert "aaaaaaaa1" in str(excinfo.value) and "aaaaaaaa2" in str(excinfo.value)
    # The full path still disambiguates; a 5-char id prefix is not an alias.
    assert sup.resolve_session(str(right)).session_id == "aaaaaaaa2"
    with pytest.raises(RuntimeError, match="Session not found: aaaaa"):
        sup.resolve_session("aaaaa")


def test_open_session_uses_matching_gui_instance(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        assert session.host == "127.0.0.1"
        assert session.port == 31337
        assert session.pid == 999
        assert sup.resolve_session("gui").session_id == "gui"
        assert sup.opened == []
    finally:
        restore()


def test_open_session_removes_stale_existing_mapping(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(sample.resolve()),
            filename="sample.bin",
            process=_DeadProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(sample.resolve()))
        session = sup.open_session(str(sample), session_id="new")
        assert session.session_id == "new"
        assert "stale" not in sup.sessions
    finally:
        restore()


def test_open_session_ignores_dead_workers_for_max_worker_limit(tmp_path):
    stale_path = tmp_path / "stale.bin"
    new_path = tmp_path / "new.bin"
    stale_path.write_bytes(b"stale")
    new_path.write_bytes(b"new")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        sup.max_workers = 1
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(stale_path.resolve()),
            filename="stale.bin",
            process=_DeadProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(stale_path.resolve()))

        session = sup.open_session(str(new_path), session_id="new")

        assert session.session_id == "new"
        assert "stale" not in sup.sessions
    finally:
        restore()


def test_resolve_session_removes_unreachable_worker(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")
    unreachable = {session.session_id}

    def fake_reachable(candidate):
        if candidate.session_id in unreachable:
            return False
        return candidate.is_alive()

    sup._session_is_reachable = fake_reachable

    with pytest.raises(RuntimeError) as excinfo:
        sup.resolve_session("sample")
    message = str(excinfo.value)
    assert "not reachable" in message
    assert "sample.bin" in message and "idb_open(input_path=" in message

    assert "sample" not in sup.sessions
    assert session.process.returncode == 0
    assert all(row["session_id"] != "sample" for row in sup.list_sessions())


def test_resolve_session_keeps_busy_worker_that_misses_ping(tmp_path):
    # A worker handles one request at a time; a ping queued behind a long call
    # times out. That must not be mistaken for a dead worker and killed.
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")
    sup._session_is_reachable = lambda _session: False
    sup._track_worker_request("transport", 7, session)

    assert sup.resolve_session("sample") is session
    assert session.process.returncode is None

    sup._untrack_worker_request("transport", 7, session)
    with pytest.raises(RuntimeError, match="not reachable"):
        sup.resolve_session("sample")


def test_list_sessions_drops_workers_whose_process_exited(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")
    session.process.returncode = 1
    monkeypatch.setattr(supmod._discovery, "discover_instances", lambda: [])

    assert sup.list_sessions() == []
    assert "sample" not in sup.sessions


def test_open_session_prunes_unreachable_existing_mapping(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(sample.resolve()),
            filename="sample.bin",
            process=_FakeProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(sample.resolve()))

        sup._session_is_reachable = lambda session: session.session_id != "stale" and session.is_alive()

        session = sup.open_session(str(sample), session_id="new")

        assert session.session_id == "new"
        assert "stale" not in sup.sessions
    finally:
        restore()


def test_probe_session_health_reports_tcp_connect_failure(monkeypatch):
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="sample.bin",
        filename="sample.bin",
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    def fail_connect(*_args, **_kwargs):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(supmod.socket, "create_connection", fail_connect)

    health = sup._probe_session_health(worker)

    assert health["reachable"] is False
    assert health["tcp_connect"] is False
    assert health["rpc_ping"] is None
    assert health["failed_probe"] == "tcp_connect"
    assert "refused" in health["error"]


def test_probe_session_health_reports_rpc_ping_failure(monkeypatch):
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="sample.bin",
        filename="sample.bin",
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(supmod.socket, "create_connection", lambda *_args, **_kwargs: _FakeSocket())
    sup._worker_rpc = lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("rpc timeout"))

    health = sup._probe_session_health(worker)

    assert health["reachable"] is False
    assert health["tcp_connect"] is True
    assert health["rpc_ping"] is False
    assert health["failed_probe"] == "rpc_ping"
    assert "rpc timeout" in health["error"]


def test_list_sessions_reports_is_active_from_health_probe(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"1")
    second.write_bytes(b"2")
    sup = _FakeSupervisor()
    sup.open_session(str(first), session_id="first")
    sup.open_session(str(second), session_id="second")

    sup._session_is_reachable = lambda session: session.session_id == "first"
    supmod._discovery.discover_instances = lambda: []

    listed = {s["session_id"]: s["is_active"] for s in sup.list_sessions()}
    assert listed == {"first": True, "second": False}


def test_close_session_saves_and_terminates_owned_worker(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")

    result = sup.close_session("sample", save=True)

    assert result["success"] is True
    assert result["saved"] is True
    assert result["owned"] is True
    assert ("idb_save", None) in sup.tool_calls
    assert "sample" not in sup.sessions
    assert sup.path_to_session == {}
    assert session.process.returncode == 0


def test_close_session_without_save_skips_idb_save(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")

    result = sup.close_session("sample", save=False)

    assert result["saved"] is None
    assert all(name != "idb_save" for name, _ in sup.tool_calls)
    assert "sample" not in sup.sessions
    assert session.process.returncode == 0


def test_close_session_unknown_session_raises():
    sup = _FakeSupervisor()
    try:
        sup.close_session("nope")
    except RuntimeError as e:
        assert "not found" in str(e)
    else:
        raise AssertionError("expected RuntimeError for unknown session")


def test_close_session_defaults_to_only_database(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")
    result = sup.close_session("", save=False)
    assert result["session_id"] == "sample"
    assert sup.sessions == {}


def test_close_session_detaches_adopted_worker_without_killing(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    adopted = supmod.WorkerSession(
        session_id="adopted",
        input_path=str(sample.resolve()),
        filename="sample.bin",
        process=_FakeProcess(),
        owned=False,
    )
    with sup._lock:
        sup._register_session_locked(adopted, str(sample.resolve()))

    result = sup.close_session("adopted", save=False)

    assert result["owned"] is False
    assert "adopted" not in sup.sessions
    assert sup.path_to_session == {}
    assert adopted.process.returncode is None


def test_close_session_reports_save_failure_but_still_closes(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _SaveFailsSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            if name == "idb_save":
                self.tool_calls.append((name, arguments))
                return {"ok": False, "path": None, "error": "disk full"}
            return super().call_worker_tool(worker, name, arguments)

    sup = _SaveFailsSupervisor()
    session = sup.open_session(str(sample), session_id="sample")

    result = sup.close_session("sample", save=True)

    assert result["saved"] is False
    assert result["save_error"] == "disk full"
    assert "sample" not in sup.sessions
    assert session.process.returncode == 0


def test_close_session_frees_worker_slot(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"1")
    second.write_bytes(b"2")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        sup.max_workers = 1
        sup.open_session(str(first), session_id="first")

        # A second open is blocked while the single slot is occupied.
        try:
            sup.open_session(str(second), session_id="second")
        except RuntimeError as e:
            assert "Maximum idalib worker count reached" in str(e)
        else:
            raise AssertionError("expected the worker limit to be reached")

        sup.close_session("first", save=False)

        reopened = sup.open_session(str(second), session_id="second")
        assert reopened.session_id == "second"
    finally:
        restore()


def test_close_session_skips_save_when_unreachable(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")
    sup._session_is_reachable = lambda candidate: False

    result = sup.close_session("sample", save=True)

    assert result["saved"] is None
    assert all(name != "idb_save" for name, _ in sup.tool_calls)
    assert "sample" not in sup.sessions
    assert session.process.returncode == 0


def test_idb_close_tool_returns_error_for_unknown_session():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod.idb_close("nope")
        assert "not found" in result["error"]
    finally:
        supmod.supervisor = old_supervisor


def test_idb_close_is_a_management_tool_symbol():
    assert "idb_close" in supmod.IDB_MANAGEMENT_TOOLS
    assert callable(supmod.idb_close)


def test_supervisor_uses_idb_prefixed_management_tools_only():
    """No legacy names should leak into IDB_MANAGEMENT_TOOLS or module symbols."""
    legacy = {
        "open_database",
        "idalib_close",
        "idalib_list",
        "idalib_save",
        "idalib_switch",
        "idalib_unbind",
        "idalib_current",
        "idalib_warmup",
        "idalib_health",
    }
    assert supmod.IDB_MANAGEMENT_TOOLS == {"idb_open", "idb_list", "idb_close"}
    for name in legacy:
        assert not hasattr(supmod, name), f"{name} should have been deleted"
    for typename in ("IdalibWarmupResult", "IdalibHealthResult"):
        assert not hasattr(supmod, typename), f"{typename} should have been deleted"
    # --stdio-shared and its support code should be gone.
    for name in (
        "_stdio_proxy",
        "_open_stdio_initial_database",
        "_ensure_shared_http_supervisor",
        "_spawn_shared_http_supervisor",
        "_probe_http_supervisor",
        "_http_jsonrpc",
        "_stdio_shared_session_id",
    ):
        assert not hasattr(supmod, name), f"{name} should have been deleted"


def test_open_session_race_discards_losing_worker_for_existing_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()))
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample))
        assert session.session_id == "winner"
        assert set(sup.sessions) == {"winner"}
        assert sup.opened[0][1]["preferred_session_id"] != "winner"
    finally:
        restore()


def test_open_session_race_returns_existing_when_preferred_id_differs(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()))
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample), session_id="loser")
        assert session.session_id == "winner"
        assert set(sup.sessions) == {"winner"}
    finally:
        restore()


def test_open_session_returns_existing_session_when_path_already_open(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    first = sup.open_session(str(sample), session_id="alpha")
    again = sup.open_session(str(sample), session_id="beta")
    assert again is first
    assert again.session_id == "alpha"
    assert set(sup.sessions) == {"alpha"}


def test_open_session_race_rejects_duplicate_session_id_for_different_path(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"1")
    second.write_bytes(b"2")

    class _RaceSupervisor(_FakeSupervisor):
        def __init__(self):
            super().__init__()
            self.spawned = []

        def _spawn_worker(self):
            worker = super()._spawn_worker()
            self.spawned.append(worker)
            return worker

        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                existing = supmod.WorkerSession(
                    session_id=arguments["preferred_session_id"],
                    input_path=str(first.resolve()),
                    filename="first.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(first.resolve()))
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        try:
            sup.open_session(str(second), session_id="shared")
        except ValueError as e:
            assert "Session already exists: shared" in str(e)
        else:
            raise AssertionError("expected ValueError")

        assert set(sup.sessions) == {"shared"}
        assert sup.sessions["shared"].input_path == str(first.resolve())
        assert sup.path_to_session.get(sup._path_key(str(second.resolve()))) is None
        assert sup.spawned[0].process.returncode == 0
    finally:
        restore()


def test_closed_gui_session_reopens_headless(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False
        reopened = sup.resolve_session("gui")
        assert reopened.backend == "worker"
        assert reopened.session_id == "gui"
        assert sup.opened[-1][1]["input_path"] == str(idb.resolve())
    finally:
        restore()


def test_closed_gui_session_falls_back_to_requested_binary_if_idb_is_stale(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        idb.unlink()
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False
        reopened = sup.resolve_session("gui")
        assert reopened.backend == "worker"
        assert reopened.session_id == "gui"
        assert sup.opened[-1][1]["input_path"] == str(sample.resolve())
    finally:
        restore()


def test_closed_gui_session_does_not_reappear_if_closed_during_headless_fallback(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")

    class _RaceSupervisor(_FakeSupervisor):
        def __init__(self):
            super().__init__()
            self.spawned = []

        def _spawn_worker(self):
            worker = super()._spawn_worker()
            self.spawned.append(worker)
            return worker

        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                # Simulate: the session disappears while the reopen worker
                # is doing the open. Drop it from the supervisor's registry
                # and tear down the spawning worker.
                sid = arguments["preferred_session_id"]
                with self._lock:
                    stale = self._unregister_session_locked(sid)
                if stale is not None:
                    self._terminate_worker(stale)
            return result

    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False

        try:
            sup.resolve_session("gui")
        except RuntimeError as e:
            assert "was closed or replaced" in str(e)
        else:
            raise AssertionError("expected RuntimeError")

        assert "gui" not in sup.sessions
        assert sup.spawned[-1].process.returncode == 0
    finally:
        restore()


def test_concurrent_open_same_path_single_idb_open(tmp_path):
    import threading

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        barrier = threading.Barrier(2)
        results: list = []

        def opener():
            barrier.wait(timeout=5)
            results.append(sup.open_session(str(sample)))

        threads = [threading.Thread(target=opener) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert all(thread.is_alive() is False for thread in threads)
        assert len(results) == 2
        assert results[0].session_id == results[1].session_id
        assert len(sup.opened) == 1
        assert sup._pending_slots == 0
        assert sup._pending_opens == {}
    finally:
        restore()


def test_terminate_worker_never_raises():
    import subprocess

    class _HangingProcess(_FakeProcess):
        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("cmd", timeout)

        def kill(self):
            raise OSError("nope")

    sup = _FakeSupervisor()
    worker = supmod.WorkerSession(
        session_id="hang",
        input_path="",
        filename="",
        process=_HangingProcess(),
    )
    sup._terminate_worker(worker)


def test_worker_open_timeout_rejects_bogus_env(monkeypatch):
    monkeypatch.setenv("IDA_MCP_OPEN_TIMEOUT", "bogus")
    assert supmod._get_worker_open_timeout_sec() == 1800.0
    monkeypatch.setenv("IDA_MCP_OPEN_TIMEOUT", "-5")
    assert supmod._get_worker_open_timeout_sec() == 1800.0


def test_open_session_rejects_evil_session_id(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        with __import__("pytest").raises(ValueError):
            sup.open_session(str(sample), session_id="../evil")
        with __import__("pytest").raises(ValueError):
            sup.open_session(str(sample), session_id="__worker_schema_x")
    finally:
        restore()


def test_spawn_failure_reports_log_tail(monkeypatch, tmp_path):
    worker = supmod.WorkerSession(
        session_id="__worker_schema_x",
        input_path="",
        filename="",
        host="127.0.0.1",
        port=1,
        process=_DeadProcess(),
        log_path=str(tmp_path / "missing.log"),
    )
    (tmp_path / "worker.log").write_bytes(b"boom\n")
    worker.log_path = str(tmp_path / "worker.log")
    sup = _FakeSupervisor()
    try:
        sup._wait_worker_ready(worker, timeout=0.1)
    except RuntimeError as e:
        assert "boom" in str(e)
        assert "log:" in str(e)
    else:
        raise AssertionError("expected RuntimeError")


def test_adoption_reads_token_sidecar(tmp_path, monkeypatch):
    from pathlib import Path as _Path

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    instances_dir = tmp_path / "instances"
    instances_dir.mkdir()
    monkeypatch.setenv("IDA_MCP_INSTANCE_DIR", str(instances_dir))
    import importlib.util as _ilu

    spec = _ilu.spec_from_file_location(
        "gui_discovery_sidecar",
        _Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp" / "discovery.py",
    )
    gui_discovery = _ilu.module_from_spec(spec)
    spec.loader.exec_module(gui_discovery)

    gui_discovery.register_instance(
        "127.0.0.1", 31415, 999999, "sample.bin", str(sample),
        backend="worker", input_file="sample.bin", auth_token="sidecar-secret",
    )
    instance = {
        "host": "127.0.0.1",
        "port": 31415,
        "pid": 999999,
        "binary": "sample.bin",
        "idb_path": str(sample),
        "started_at": "now",
        "backend": "worker",
    }
    restore = _patch_discovery(instances=[instance], probe=True)
    try:
        sup = _FakeSupervisor()
        sup._session_is_reachable = lambda session: True
        adopted = sup._adopt_worker_instance(str(sample), "adopted", instance)
        assert adopted is not None
        assert adopted.auth_token == "sidecar-secret"
        assert (instances_dir / "instance_31415.token").exists()
    finally:
        restore()


class _SlowOpenSupervisor(_FakeSupervisor):
    """idb_open blocks until ``release`` is set, like a long auto-analysis."""

    def __init__(self):
        super().__init__()
        self.release = threading.Event()
        self.fail_with: str | None = None

    def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
        if name == "idb_open":
            assert self.release.wait(5)
            if self.fail_with:
                raise RuntimeError(self.fail_with)
        return super().call_worker_tool(worker, name, arguments, timeout=timeout)


def _wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached")


def _call(name, arguments):
    return supmod._handle_tools_call(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )


def test_open_past_wait_budget_fails_fast_until_ready(tmp_path, monkeypatch):
    sample = tmp_path / "big.exe"
    sample.write_bytes(b"x")
    sup = _SlowOpenSupervisor()
    monkeypatch.setattr(supmod, "supervisor", sup)
    monkeypatch.setattr(supmod._discovery, "discover_instances", lambda: [])
    monkeypatch.setenv("IDA_MCP_OPEN_WAIT_SEC", "0.05")

    opened = supmod.idb_open(str(sample), preferred_session_id="big")
    assert opened["session"]["session_id"] == "big"
    assert opened["session"]["state"] == "opening"
    assert "wait budget" in opened["warning"]
    # Re-opening the same path joins the pending open instead of spawning another.
    assert supmod.idb_open(str(sample), wait=False)["session"]["session_id"] == "big"
    assert [(row["session_id"], row["state"]) for row in sup.list_sessions()] == [("big", "opening")]

    blocked = _call("decompile", {"addr": "0x1"})  # database defaults to the opening one
    text = blocked["result"]["content"][0]["text"]
    assert blocked["result"]["isError"] is True
    assert "Session 'big.exe' is still analyzing (elapsed" in text and "idb_list" in text
    assert not sup.forwarded

    sup.release.set()
    _wait_until(lambda: "big" in sup.sessions and not sup._open_jobs)
    assert _call("decompile", {"addr": "0x1", "database": "big.exe"})["result"] == {"ok": True}
    assert [row["state"] for row in sup.list_sessions()] == ["ready"]
    assert len([name for name, _ in sup.opened]) == 1


def test_open_failure_inside_budget_raises_and_leaves_no_job(tmp_path, monkeypatch):
    sample = tmp_path / "bad.exe"
    sample.write_bytes(b"x")
    monkeypatch.setattr(supmod._discovery, "discover_instances", lambda: [])
    sup = _SlowOpenSupervisor()
    sup.fail_with = "boom"
    sup.release.set()
    with pytest.raises(RuntimeError, match="boom"):
        sup.start_open(str(sample), wait_sec=5)
    assert sup._open_jobs == {} and sup.sessions == {}


def test_background_open_failure_is_listed_then_discarded(tmp_path, monkeypatch):
    sample = tmp_path / "bad.exe"
    sample.write_bytes(b"x")
    monkeypatch.setattr(supmod._discovery, "discover_instances", lambda: [])
    sup = _SlowOpenSupervisor()
    sup.fail_with = "analysis crashed"
    job = sup.start_open(str(sample), wait_sec=0, session_id="bad")
    assert isinstance(job, supmod.OpenJob)
    sup.release.set()
    _wait_until(lambda: job.state == "failed")

    [row] = sup.list_sessions()
    assert row["state"] == "failed" and "analysis crashed" in row["error"]
    with pytest.raises(RuntimeError, match="failed to open: analysis crashed"):
        sup.resolve_session("bad.exe")
    with pytest.raises(RuntimeError, match="No database is open"):
        sup.resolve_session(None)  # a failed open is never the default
    assert sup.close_session("bad")["success"] is True
    assert sup.list_sessions() == []


def test_binary_diff_resolves_left_and_right_aliases(tmp_path, monkeypatch):
    old = tmp_path / "old.bin"
    new = tmp_path / "new.bin"
    old.write_bytes(b"1")
    new.write_bytes(b"2")
    sup = _FakeSupervisor()
    sup.open_session(str(old), session_id="left1")
    sup.open_session(str(new), session_id="right1")
    monkeypatch.setattr(supmod, "supervisor", sup)

    result = _call(
        "analysis_run",
        {"database": "old", "mode": "binary_diff", "options": {"right_database": "new.bin"}},
    )["result"]
    assert result["isError"] is False
    data = result["structuredContent"]["data"]
    assert (data["left_database"], data["right_database"]) == ("left1", "right1")
    assert not sup.forwarded


def test_initialize_returns_usage_instructions():
    response = supmod.dispatch_supervisor(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
        }
    )
    instructions = response["result"]["instructions"]
    assert 'analysis_run(mode="triage")' in instructions
    assert "database= is optional" in instructions
    assert len(instructions.splitlines()) <= 25
    assert "instructions" not in supmod.McpServer("plain")._mcp_initialize("2025-06-18", {}, {})
