import json
import threading

from ida_pro_mcp import bridge_server

import pytest


def _tool(name):
    return {"name": name, "description": "", "inputSchema": {"type": "object", "properties": {}}}


def test_single_instance_unprefixed(discovery):
    target = discovery.InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="")
    table = discovery.build_tool_table([target], {"a": [_tool("decompile"), _tool("xrefs_to")]})
    names = {t["name"] for t in table.list_tools()}
    assert names == {"ida_list_instances", "decompile", "xrefs_to"}


def test_two_instances_prefixed_and_shared_withdrawn(discovery):
    a = discovery.InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="crackme_exe__")
    b = discovery.InstanceTarget(id="b", host="127.0.0.1", port=13338, prefix="library_dll__")
    tools = {"a": [_tool("decompile")], "b": [_tool("decompile")]}
    table = discovery.build_tool_table([a, b], tools)
    names = {t["name"] for t in table.list_tools()}
    assert "decompile" not in names  # ambiguous shared name withdrawn
    assert "crackme_exe__decompile" in names
    assert "library_dll__decompile" in names
    assert "ida_list_instances" in names


def test_route_resolves_prefixed_name(discovery):
    a = discovery.InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="crackme_exe__")
    b = discovery.InstanceTarget(id="b", host="127.0.0.1", port=13338, prefix="library_dll__")
    tools = {"a": [_tool("decompile")], "b": [_tool("decompile")]}
    table = discovery.build_tool_table([a, b], tools)
    host, port, inner = discovery.route_tool_call(table, "library_dll__decompile")
    assert (host, port) == ("127.0.0.1", 13338)
    assert inner == "decompile"  # prefix stripped before proxying


def test_route_unknown_prefix_raises(discovery):
    a = discovery.InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="crackme_exe__")
    b = discovery.InstanceTarget(id="b", host="127.0.0.1", port=13338, prefix="library_dll__")
    table = discovery.build_tool_table([a, b], {"a": [_tool("decompile")], "b": [_tool("decompile")]})
    with pytest.raises(KeyError, match="ida_list_instances"):
        discovery.route_tool_call(table, "ghost__decompile")


def test_single_instance_keeps_unprefixed_names(discovery):
    target = discovery.InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="")
    table = discovery.build_tool_table([target], {"a": [_tool("decompile")]})
    host, port, inner = discovery.route_tool_call(table, "decompile")
    assert (host, port, inner) == ("127.0.0.1", 13337, "decompile")


def test_failed_tool_fetch_is_retried(monkeypatch):
    instance = {"host": "127.0.0.1", "port": 13337, "pid": 1, "input_file": "input.bin"}
    attempts = []
    monkeypatch.setattr(
        bridge_server._discovery,
        "read_registry_dir",
        lambda _path: [instance],
    )
    monkeypatch.setattr(bridge_server._discovery, "get_instances_dir", lambda: "unused")

    def fetch(_host, _port):
        attempts.append(True)
        if len(attempts) == 1:
            raise OSError("not ready")
        return [_tool("decompile")]

    monkeypatch.setattr(bridge_server, "_fetch_tools_for", fetch)
    monkeypatch.setattr(bridge_server, "_emit_tools_list_changed", lambda: None)
    bridge_server._tool_table = None
    bridge_server._tool_table_signature = None
    bridge_server._tool_fetch_failures = set()

    first = bridge_server._refresh_tool_table()
    second = bridge_server._refresh_tool_table()

    assert {tool["name"] for tool in first.list_tools()} == {"ida_list_instances"}
    assert {tool["name"] for tool in second.list_tools()} == {
        "ida_list_instances",
        "decompile",
    }
    assert len(attempts) == 2


def test_force_refresh_replaces_changed_tool_schema(monkeypatch):
    instance = {"host": "127.0.0.1", "port": 13337, "pid": 1, "input_file": "input.bin"}
    advertised = [[_tool("decompile")], [_tool("rename")]]
    changed = []
    monkeypatch.setattr(
        bridge_server._discovery,
        "read_registry_dir",
        lambda _path: [instance],
    )
    monkeypatch.setattr(bridge_server._discovery, "get_instances_dir", lambda: "unused")
    monkeypatch.setattr(
        bridge_server,
        "_fetch_tools_for",
        lambda _host, _port: advertised.pop(0),
    )
    monkeypatch.setattr(
        bridge_server,
        "_emit_tools_list_changed",
        lambda: changed.append(True),
    )
    bridge_server._tool_table = None
    bridge_server._tool_table_signature = None
    bridge_server._tool_fetch_failures = set()

    bridge_server._refresh_tool_table(force=True)
    refreshed = bridge_server._refresh_tool_table(force=True)

    assert {tool["name"] for tool in refreshed.list_tools()} == {
        "ida_list_instances",
        "rename",
    }
    assert changed == [True]


def test_cancellation_uses_inflight_tool_route(monkeypatch):
    target = bridge_server._discovery.InstanceTarget(
        id="instance-a",
        host="127.0.0.1",
        port=13337,
        prefix="",
    )
    table = bridge_server._discovery.build_tool_table(
        [target],
        {"instance-a": [_tool("decompile")]},
    )
    tool_started = threading.Event()
    release_tool = threading.Event()
    forwarded = []

    def post(payload, host, port):
        request = json.loads(payload)
        forwarded.append((request, host, port))
        if request["method"] == "tools/call":
            tool_started.set()
            assert release_tool.wait(2)
        return bridge_server.JsonRpcResponse(
            {"jsonrpc": "2.0", "id": request.get("id"), "result": {}}
        )

    monkeypatch.setattr(bridge_server, "_refresh_tool_table", lambda **_kwargs: table)
    monkeypatch.setattr(bridge_server, "_post_to_ida", post)
    bridge_server._pending_routes.clear()
    thread = threading.Thread(
        target=bridge_server.dispatch_proxy,
        args=(
            {
                "jsonrpc": "2.0",
                "id": 73,
                "method": "tools/call",
                "params": {"name": "decompile", "arguments": {}},
            },
        ),
    )
    thread.start()
    assert tool_started.wait(2)

    result = bridge_server.dispatch_proxy(
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 73, "reason": "test"},
        }
    )
    release_tool.set()
    thread.join(2)

    assert result is None
    assert thread.is_alive() is False
    cancellation = next(
        item for item in forwarded if item[0]["method"] == "notifications/cancelled"
    )
    assert cancellation[1:] == ("127.0.0.1", 13337)


def test_tools_call_forwards_transport_session_and_bearer(monkeypatch):
    target = bridge_server._discovery.InstanceTarget(
        id="instance-a", host="127.0.0.1", port=13337, prefix="",
    )
    table = bridge_server._discovery.build_tool_table(
        [target], {"instance-a": [{"name": "decompile", "description": "", "inputSchema": {"type": "object", "properties": {}}}]},
    )
    seen = {}
    def fake_refresh(**_kwargs):
        return table
    def fake_post(payload, host, port):
        request = json.loads(payload)
        seen["headers"] = bridge_server._get_proxy_request_headers()
        return bridge_server.JsonRpcResponse({"jsonrpc": "2.0", "id": request.get("id"), "result": {}})
    monkeypatch.setattr(bridge_server, "_refresh_tool_table", fake_refresh)
    monkeypatch.setattr(bridge_server, "_post_to_ida", fake_post)
    monkeypatch.setattr(bridge_server.mcp._transport_session_id, "data", "http:session-456", raising=False)
    monkeypatch.setattr(bridge_server, "_BRIDGE_AUTH_TOKEN", "t", raising=False)
    try:
        resp = bridge_server.dispatch_proxy(
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
             "params": {"name": "decompile", "arguments": {}}}
        )
    finally:
        monkeypatch.setattr(bridge_server.mcp._transport_session_id, "data", None, raising=False)
        monkeypatch.setattr(bridge_server, "_BRIDGE_AUTH_TOKEN", None, raising=False)
    assert resp is not None
    assert seen["headers"]["Mcp-Session-Id"] == "session-456"
    assert seen["headers"]["Authorization"] == "Bearer t"
    assert bridge_server._pending_routes == {}


def test_tools_list_uses_ttl_cache(monkeypatch):
    calls = []
    instance = {"host": "127.0.0.1", "port": 13337, "pid": 1, "input_file": "a.exe"}
    monkeypatch.setattr(
        bridge_server._discovery, "read_registry_dir", lambda _path: [instance],
    )
    monkeypatch.setattr(bridge_server._discovery, "get_instances_dir", lambda: "unused")
    monkeypatch.setattr(
        bridge_server, "_fetch_tools_for", lambda _h, _p: calls.append(1) or [],
    )
    monkeypatch.setattr(bridge_server, "_emit_tools_list_changed", lambda: None)
    bridge_server._tool_table = None
    bridge_server._tool_table_signature = None
    bridge_server._tool_fetch_failures = set()
    bridge_server._tool_table_fetched_at = None
    first = bridge_server.dispatch_proxy({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    second = bridge_server.dispatch_proxy({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert first is not None and second is not None
    assert len(calls) == 1
