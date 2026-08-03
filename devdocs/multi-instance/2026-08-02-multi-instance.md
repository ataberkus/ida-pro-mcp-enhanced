# Multi-Instance IDA MCP Support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one MCP client discover and target any number of running IDA instances by name, via a stdio bridge that routes by tool-name prefix.

**Architecture:** Each IDA plugin auto-starts its HTTP server on load (auto-incremented port) and writes a host-local registry JSON file. The stdio bridge (`bridge_server.py`) discovers live instances from the registry, and re-exposes each instance's tools under a per-instance prefix (`crackme_exe__decompile`). Single instance → unprefixed tools (backward compatible).

**Tech Stack:** Python 3.11+, IDA SDK (plugin side), plain stdlib HTTP/JSON-RPC (bridge side), pytest (bridge unit tests), in-IDA test framework (plugin tests).

**Spec:** [docs/superpowers/specs/2026-08-02-multi-instance-design.md](../specs/2026-08-02-multi-instance-design.md)

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `ida_mcp/registry.py` | Plugin-side: compute registry dir, write/remove instance registry file | Create |
| `ida_mcp.py` | Plugin entry: auto-start server on DB load, call registry write/remove | Modify |
| `ida_mcp/tests/test_registry.py` | In-IDA tests for registry path + file contents | Create |
| `bridge_server.py` | Bridge: discovery, prefixing, routing, `tools/list_changed` | Modify (heavy) |
| `ida_mcp/bridge_discovery.py` | Bridge-side pure-Python discovery + prefix logic (unit-testable, no IDA) | Create |
| `tests_bridge/test_discovery.py` | pytest unit tests for discovery/prefix/routing | Create |

Note: bridge-side logic lives in a **new importable module** `ida_mcp/bridge_discovery.py` so it can be unit-tested with plain pytest (no IDA). `bridge_server.py` imports it. Plugin-side registry writes use the stdlib only (no IDA APIs needed for the file itself), so `registry.py` is also pytest-friendly; the IDA-specific bits (idb path, input file) are injected as arguments.

---

## Task 1: Bridge-side discovery module (`ida_mcp/bridge_discovery.py`)

Pure-Python, no IDA imports. This is the core that everything else uses.

**Files:**
- Create: `ida_mcp/bridge_discovery.py`
- Test: `tests_bridge/test_discovery.py`

- [ ] **Step 1: Write the failing test**

Create `tests_bridge/test_discovery.py`:

```python
import json
import os
import time
from ida_mcp.discovery import (
    InstanceInfo,
    sanitize_prefix,
    read_registry_dir,
    assign_prefixes,
)


def test_sanitize_prefix_basic():
    assert sanitize_prefix("crackme.exe") == "crackme_exe"
    assert sanitize_prefix("My Library.DLL") == "my_library_dll"
    assert sanitize_prefix("weird@@file$$name") == "weird_file_name"


def test_read_registry_dir_live(tmp_path):
    inst = {
        "id": "pid1234-a1b2c3",
        "pid": os.getpid(),  # current process is definitely alive
        "host": "127.0.0.1",
        "port": 13337,
        "session_id": "s",
        "idb_path": "C:/work/crackme.exe.i64",
        "input_file": "crackme.exe",
        "started_at": "2026-08-02T12:00:00Z",
    }
    (tmp_path / f"{inst['id']}.json").write_text(json.dumps(inst))
    live = read_registry_dir(str(tmp_path), probe=False)
    assert len(live) == 1
    assert live[0].input_file == "crackme.exe"
    assert live[0].port == 13337


def test_read_registry_dir_drops_dead_pid(tmp_path):
    inst = {
        "id": "dead", "pid": 99999999, "host": "127.0.0.1", "port": 13337,
        "session_id": "s", "idb_path": "x", "input_file": "x.exe",
        "started_at": "2026-08-02T12:00:00Z",
    }
    (tmp_path / "dead.json").write_text(json.dumps(inst))
    assert read_registry_dir(str(tmp_path), probe=False) == []


def test_assign_prefixes_single_no_prefix():
    a = InstanceInfo("a", 1, "127.0.0.1", 13337, "s", "i", "crackme.exe", "t")
    mapping = assign_prefixes([a])
    assert mapping["a"] == ""  # single instance: unprefixed


def test_assign_prefixes_two_prefixed():
    a = InstanceInfo("a", 1, "127.0.0.1", 13337, "s", "i", "crackme.exe", "t")
    b = InstanceInfo("b", 2, "127.0.0.1", 13338, "s", "i", "library.dll", "t")
    mapping = assign_prefixes([a, b])
    assert mapping["a"] == "crackme_exe__"
    assert mapping["b"] == "library_dll__"


def test_assign_prefixes_collision_disambiguates():
    a = InstanceInfo("aaa111", 1, "127.0.0.1", 13337, "s", "i", "same.exe", "t")
    b = InstanceInfo("bbb222", 2, "127.0.0.1", 13338, "s", "i", "same.exe", "t")
    mapping = assign_prefixes([a, b])
    assert mapping["aaa111"] != mapping["bbb222"]
    assert mapping["aaa111"].startswith("same_exe_")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests_bridge/test_discovery.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ida_mcp.discovery'`

- [ ] **Step 3: Write minimal implementation**

Create `ida_mcp/bridge_discovery.py`:

```python
"""Host-local discovery of running IDA MCP instances (bridge side, no IDA deps)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass


@dataclass
class InstanceInfo:
    id: str
    pid: int
    host: str
    port: int
    session_id: str
    idb_path: str
    input_file: str
    started_at: str


def sanitize_prefix(name: str) -> str:
    """Make an input file name a valid tool-name token."""
    s = name.lower()
    s = re.sub(r"[^a-z0-9_]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "ida"


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_registry_dir(registry_dir: str, probe: bool = True) -> list[InstanceInfo]:
    """Read registry JSON files, dropping entries whose PID is dead.

    probe=True additionally checks the port answers; kept injectable for tests.
    """
    out: list[InstanceInfo] = []
    if not os.path.isdir(registry_dir):
        return out
    for fname in os.listdir(registry_dir):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(registry_dir, fname), "r", encoding="utf-8") as f:
                d = json.load(f)
            inst = InstanceInfo(
                id=d["id"], pid=int(d["pid"]), host=d["host"], port=int(d["port"]),
                session_id=d.get("session_id", ""), idb_path=d.get("idb_path", ""),
                input_file=d.get("input_file", ""), started_at=d.get("started_at", ""),
            )
        except (OSError, ValueError, KeyError):
            continue
        if not _pid_alive(inst.pid):
            continue
        out.append(inst)
    return out


def assign_prefixes(instances: list[InstanceInfo]) -> dict[str, str]:
    """Map instance id -> tool prefix. Single instance => '' (unprefixed)."""
    if len(instances) == 1:
        return {instances[0].id: ""}
    prefixes: dict[str, str] = {}
    seen: dict[str, list[str]] = {}
    for inst in instances:
        base = sanitize_prefix(inst.input_file)
        seen.setdefault(base, []).append(inst.id)
    for base, ids in seen.items():
        if len(ids) == 1:
            prefixes[ids[0]] = f"{base}__"
        else:
            for iid in ids:
                prefixes[iid] = f"{base}_{iid[:4]}__"
    return prefixes
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests_bridge/test_discovery.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add ida_mcp/bridge_discovery.py tests_bridge/test_discovery.py
git commit -m "feat(bridge): add host-local instance discovery and prefix assignment"
```

---

## Task 2: Plugin-side registry writer (`ida_mcp/registry.py`)

Stdlib-only file write/remove; IDA specifics injected by the caller.

**Files:**
- Create: `ida_mcp/registry.py`
- Test: `tests_bridge/test_registry_writer.py`

- [ ] **Step 1: Write the failing test**

Create `tests_bridge/test_registry_writer.py`:

```python
import json
import os
from ida_mcp.registry import registry_dir, write_instance, remove_instance, INSTANCE_ENV


def test_registry_dir_uses_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv(INSTANCE_ENV, str(tmp_path))
    assert registry_dir() == str(tmp_path)


def test_write_and_remove_instance(tmp_path, monkeypatch):
    monkeypatch.setenv(INSTANCE_ENV, str(tmp_path))
    payload = write_instance(
        pid=os.getpid(), host="127.0.0.1", port=13337,
        idb_path="C:/work/crackme.exe.i64", input_file="crackme.exe",
    )
    path = os.path.join(str(tmp_path), f"{payload['id']}.json")
    assert os.path.isfile(path)
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["input_file"] == "crackme.exe"
    assert data["port"] == 13337
    assert data["pid"] == os.getpid()
    remove_instance(payload["id"])
    assert not os.path.exists(path)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests_bridge/test_registry_writer.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ida_mcp.registry'`

- [ ] **Step 3: Write minimal implementation**

Create `ida_mcp/registry.py`:

```python
"""Plugin-side instance registry file management (stdlib only)."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

INSTANCE_ENV = "IDA_MCP_INSTANCE_DIR"


def registry_dir() -> str:
    override = os.environ.get(INSTANCE_ENV)
    if override:
        return override
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "ida-mcp", "instances")
    return os.path.join(os.path.expanduser("~"), ".local", "share", "ida-mcp", "instances")


def write_instance(pid: int, host: str, port: int, idb_path: str, input_file: str) -> dict:
    os.makedirs(registry_dir(), exist_ok=True)
    payload = {
        "id": f"pid{pid}-{uuid.uuid4().hex[:6]}",
        "pid": pid,
        "host": host,
        "port": port,
        "session_id": uuid.uuid4().hex,
        "idb_path": idb_path,
        "input_file": input_file,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    path = os.path.join(registry_dir(), f"{payload['id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    return payload


def remove_instance(instance_id: str) -> None:
    path = os.path.join(registry_dir(), f"{instance_id}.json")
    try:
        os.remove(path)
    except OSError:
        pass
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests_bridge/test_registry_writer.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add ida_mcp/registry.py tests_bridge/test_registry_writer.py
git commit -m "feat(plugin): add instance registry file writer"
```

---

## Task 3: Plugin auto-start + registry hookup (`ida_mcp.py`)

Wire the registry into the plugin lifecycle and auto-start the server on DB load.

**Files:**
- Modify: `ida_mcp.py` (the `MCP.init` / `MCP.run` / `MCP.term` methods)

- [ ] **Step 1: Capture idb/input metadata and write registry after successful serve**

In `ida_mcp.py`, modify the `run` method's success branch (after `MCP_SERVER.serve(...)` succeeds). The current success block ends with `self.mcp = MCP_SERVER; return`. Insert registry write using IDA metadata helpers:

```python
                MCP_SERVER.serve(
                    self.host, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(f"  Config: http://{self.host}:{port}/config.html")
                self.mcp = MCP_SERVER
                self._bound_port = port
                self._register_instance(port)
                return
```

Add these methods to the `MCP` class:

```python
    def _register_instance(self, port: int) -> None:
        try:
            import os
            import ida_nalt
            import ida_loader
            from ida_mcp.registry import write_instance

            idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
            input_file = ida_nalt.get_root_filename() or ""
            self._instance = write_instance(
                pid=os.getpid(),
                host=self.host,
                port=port,
                idb_path=idb_path,
                input_file=input_file,
            )
            print(f"[MCP] Registered instance {self._instance['id']} ({input_file})")
        except Exception as e:
            print(f"[MCP] Instance registration failed: {e}")
            self._instance = None

    def _unregister_instance(self) -> None:
        inst = getattr(self, "_instance", None)
        if not inst:
            return
        try:
            from ida_mcp.registry import remove_instance

            remove_instance(inst["id"])
        except Exception as e:
            print(f"[MCP] Instance unregistration failed: {e}")
        self._instance = None
```

- [ ] **Step 2: Unregister on stop and term**

In `run`, the stop branch at the top currently is `if self.mcp: self.mcp.stop(); self.mcp = None`. Update it to also unregister:

```python
        if self.mcp:
            self.mcp.stop()
            self.mcp = None
            self._unregister_instance()
```

In `term`, after `self.mcp.stop()`, add `self._unregister_instance()`.

- [ ] **Step 3: Auto-start on database load**

Add a UI hook so the server starts once IDA has loaded a database. Add to the `MCP` class alongside `MCPUIHooks`:

```python
class MCPAutoStartHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin: "MCP"):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        # IDA finished initial UI + DB load; start the server once.
        if self.plugin.mcp is None:
            self.plugin.run(0)
        self.unhook()
```

In `init`, initialize the new fields and hook auto-start. After `self.mcp = None` add `self._instance = None` and `self._bound_port = None`, and hook it:

```python
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self._instance = None
        self._bound_port = None
        self.host = self.DEFAULT_HOST
        self.port = self.DEFAULT_PORT
        self._autostart = MCPAutoStartHooks(self)
        self._autostart.hook()
```

In `term`, unhook it: `if hasattr(self, "_autostart"): self._autostart.unhook()`.

- [ ] **Step 4: Manual verification in IDA**

Open one IDA, load any binary. Confirm the Output window shows `Registered instance ...` and a JSON file appears under `%LOCALAPPDATA%\ida-mcp\instances\`. Open a second IDA with a different binary; confirm a second file appears with a different port. Close one; confirm its file is removed.

- [ ] **Step 5: Commit**

```bash
git add ida_mcp.py
git commit -m "feat(plugin): auto-start server on load and register instance"
```

---

## Task 4: Bridge routing + tool prefixing (`bridge_server.py`)

Replace single-target proxy with discovery-driven routing and namespaced tools.

**Files:**
- Modify: `bridge_server.py` (the `dispatch_proxy`, `_get_tools_list`, `_post_to_ida` functions and module globals)
- Test: `tests_bridge/test_bridge_routing.py`

- [ ] **Step 1: Write the failing test**

Create `tests_bridge/test_bridge_routing.py`:

```python
from server import (
    build_tool_table,
    route_tool_call,
    InstanceTarget,
)


def _tool(name):
    return {"name": name, "description": "", "inputSchema": {"type": "object", "properties": {}}}


def test_single_instance_unprefixed():
    target = InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="")
    table = build_tool_table([target], {"a": [_tool("decompile"), _tool("xrefs_to")]})
    names = {t["name"] for t in table.list_tools()}
    assert names == {"ida_list_instances", "decompile", "xrefs_to"}


def test_two_instances_prefixed_and_shared_withdrawn():
    a = InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="crackme_exe__")
    b = InstanceTarget(id="b", host="127.0.0.1", port=13338, prefix="library_dll__")
    tools = {"a": [_tool("decompile")], "b": [_tool("decompile")]}
    table = build_tool_table([a, b], tools)
    names = {t["name"] for t in table.list_tools()}
    assert "decompile" not in names  # ambiguous shared name withdrawn
    assert "crackme_exe__decompile" in names
    assert "library_dll__decompile" in names
    assert "ida_list_instances" in names


def test_route_resolves_prefixed_name():
    a = InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="crackme_exe__")
    b = InstanceTarget(id="b", host="127.0.0.1", port=13338, prefix="library_dll__")
    tools = {"a": [_tool("decompile")], "b": [_tool("decompile")]}
    table = build_tool_table([a, b], tools)
    host, port, inner = route_tool_call(table, "library_dll__decompile")
    assert (host, port) == ("127.0.0.1", 13338)
    assert inner == "decompile"  # prefix stripped before proxying


def test_route_unknown_prefix_raises():
    a = InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="crackme_exe__")
    b = InstanceTarget(id="b", host="127.0.0.1", port=13338, prefix="library_dll__")
    table = build_tool_table([a, b], {"a": [_tool("decompile")], "b": [_tool("decompile")]})
    try:
        route_tool_call(table, "ghost__decompile")
    except KeyError as e:
        assert "ida_list_instances" in str(e)
    else:
        raise AssertionError("expected KeyError")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests_bridge/test_bridge_routing.py -v`
Expected: FAIL — `ImportError: cannot import name 'build_tool_table' from 'server'`

- [ ] **Step 3: Write minimal implementation**

In `bridge_server.py`, add near the top (after imports):

```python
from dataclasses import dataclass, field

from ida_mcp.discovery import read_registry_dir, assign_prefixes, registry_dir  # noqa: F401


@dataclass
class InstanceTarget:
    id: str
    host: str
    port: int
    prefix: str


@dataclass
class ToolTable:
    targets: list[InstanceTarget]
    # exposed_name -> (target, inner_name)
    routes: dict[str, tuple[InstanceTarget, str]] = field(default_factory=dict)
    schemas: dict[str, dict] = field(default_factory=dict)

    def list_tools(self) -> list[dict]:
        return list(self.schemas.values())


def build_tool_table(targets: list[InstanceTarget], tools_by_id: dict[str, list[dict]]) -> ToolTable:
    table = ToolTable(targets=targets)
    for target in targets:
        for tool in tools_by_id.get(target.id, []):
            inner = tool["name"]
            exposed = f"{target.prefix}{inner}"
            if target.prefix == "" or exposed not in table.routes:
                table.routes[exposed] = (target, inner)
                schema = dict(tool)
                schema["name"] = exposed
                table.schemas[exposed] = schema
    # shared bridge-local tool
    table.schemas["ida_list_instances"] = {
        "name": "ida_list_instances",
        "description": "List running IDA instances and their tool prefixes.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    return table


def route_tool_call(table: ToolTable, exposed_name: str) -> tuple[str, int, str]:
    if exposed_name not in table.routes:
        raise KeyError(
            f"Unknown or unavailable tool '{exposed_name}'. "
            "Call ida_list_instances to see live instances and prefixes."
        )
    target, inner = table.routes[exposed_name]
    return target.host, target.port, inner
```

Then change `_post_to_ida` to accept host/port explicitly:

```python
def _post_to_ida(payload: bytes, host: str, port: int) -> dict:
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.request(
            "POST", "/mcp", payload,
            {"Content-Type": "application/json", "Mcp-Session-Id": BRIDGE_SESSION_ID},
        )
        response = conn.getresponse()
        raw_data = response.read().decode()
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status} {response.reason}: {raw_data}")
        return json.loads(raw_data)
    finally:
        conn.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests_bridge/test_bridge_routing.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add bridge_server.py tests_bridge/test_bridge_routing.py
git commit -m "feat(bridge): add tool table, prefix routing, and explicit-target POST"
```

---

## Task 5: Wire dispatch_proxy to the tool table

Make the live request path use discovery + routing instead of the single global.

**Files:**
- Modify: `bridge_server.py` (`dispatch_proxy`, `_get_tools_list`, and the module globals `IDA_HOST`/`IDA_PORT`)

- [ ] **Step 1: Refresh tool table per request with change detection**

Replace the `_tools_cache` global and `_get_tools_list` with discovery-driven table building:

```python
_tool_table: ToolTable | None = None
_tool_table_signature: tuple | None = None


def _refresh_tool_table() -> ToolTable:
    global _tool_table, _tool_table_signature
    instances = read_registry_dir(registry_dir())
    prefixes = assign_prefixes(instances)
    targets = [
        InstanceTarget(id=i.id, host=i.host, port=i.port, prefix=prefixes[i.id])
        for i in instances
    ]
    signature = tuple(sorted((t.id, t.port, t.prefix) for t in targets))
    if _tool_table is None or signature != _tool_table_signature:
        tools_by_id = {}
        for t in targets:
            tools_by_id[t.id] = _fetch_tools_for(t.host, t.port)
        _tool_table = build_tool_table(targets, tools_by_id)
        changed = _tool_table_signature is not None
        _tool_table_signature = signature
        if changed:
            _emit_tools_list_changed()
    return _tool_table


def _fetch_tools_for(host: str, port: int) -> list[dict]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}}
    ).encode("utf-8")
    resp = _post_to_ida(payload, host, port)
    result = resp.get("result", resp)
    return result.get("tools", []) if isinstance(result, dict) else []


def _emit_tools_list_changed() -> None:
    # stdio: best-effort notification; clients that support it will refresh.
    note = json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
    try:
        sys.stdout.write(note + "\n")
        sys.stdout.flush()
    except Exception:
        pass
```

- [ ] **Step 2: Route tools/call and tools/list through the table**

In `dispatch_proxy`, replace the `tools/list` branch and the proxy fallthrough:

```python
    if method == "tools/list":
        request_id = request_obj.get("id")
        try:
            result = {"tools": _refresh_tool_table().list_tools()}
        except Exception as e:
            result = {"tools": [], "error": str(e)}
        return JsonRpcResponse({"jsonrpc": "2.0", "result": result, "id": request_id})

    if method == "tools/call":
        request_id = request_obj.get("id")
        params = request_obj.get("params", {})
        exposed = params.get("name", "")
        table = _refresh_tool_table()
        if exposed == "ida_list_instances":
            items = [
                {"id": t.id, "host": t.host, "port": t.port, "tool_prefix": t.prefix}
                for t in table.targets
            ]
            return JsonRpcResponse({
                "jsonrpc": "2.0",
                "result": {"content": [{"type": "text", "text": json.dumps(items)}]},
                "id": request_id,
            })
        try:
            host, port, inner = route_tool_call(table, exposed)
        except KeyError as e:
            return JsonRpcResponse({
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": str(e)},
                "id": request_id,
            })
        params["name"] = inner  # strip prefix before proxying
        payload = json.dumps({**request_obj, "params": params}).encode("utf-8")
        return _post_to_ida(payload, host, port)
```

Leave the existing generic fallthrough (initialize/notifications) intact, but update its `_post_to_ida(payload)` call to pass the default single target when only one instance exists — or, if none, return the existing "did you start the server" error. When `--ida-rpc` is explicitly set, keep the legacy single-target behavior by seeding the table with that one target.

- [ ] **Step 3: Manual end-to-end check**

Start two IDAs (auto-registered), run the bridge over stdio, and confirm: `tools/list` shows prefixed names; a `tools/call` to a prefixed name reaches the right IDA; closing one IDA drops its tools on the next `tools/list`.

- [ ] **Step 4: Run full bridge test suite**

Run: `pytest tests_bridge -v`
Expected: all PASS (discovery + registry + routing)

- [ ] **Step 5: Commit**

```bash
git add bridge_server.py
git commit -m "feat(bridge): route requests through discovery-driven tool table"
```

---

## Task 6: Regression — single-instance behavior unchanged

**Files:**
- Test: `tests_bridge/test_bridge_routing.py` (extend)

- [ ] **Step 1: Add single-instance end-to-end assertions**

Append to `tests_bridge/test_bridge_routing.py`:

```python
def test_single_instance_keeps_unprefixed_names():
    target = InstanceTarget(id="a", host="127.0.0.1", port=13337, prefix="")
    table = build_tool_table([target], {"a": [_tool("decompile")]})
    host, port, inner = route_tool_call(table, "decompile")
    assert (host, port, inner) == ("127.0.0.1", 13337, "decompile")
```

- [ ] **Step 2: Run all bridge tests**

Run: `pytest tests_bridge -v`
Expected: all PASS

- [ ] **Step 3: Run existing in-IDA suite**

Follow the repo's in-IDA test runner for `ida_mcp/tests` to confirm no plugin regressions.

- [ ] **Step 4: Commit**

```bash
git add tests_bridge/test_bridge_routing.py
git commit -m "test(bridge): assert single-instance unprefixed behavior"
```

---

## Self-Review Notes

- **Spec coverage:** registry write/remove (T2, T3), auto-start (T3), discovery + stale-drop (T1), prefix sanitization + collision (T1), tool-namespacing + shared-set withdrawal (T4), `ida_list_instances` (T4/T5), `tools/list_changed` (T5), dead-prefix error (T4/T5), single-IDA backward compat (T6), stdio config change (documented; no code). All spec sections map to a task.
- **Placeholder scan:** every code step contains complete code; no TBD/TODO.
- **Type consistency:** `InstanceInfo` (discovery) ↔ `InstanceTarget` (server) fields align (`id/host/port/prefix`); `_post_to_ida(payload, host, port)` signature used consistently in T4/T5; `route_tool_call` returns `(host, port, inner)` consistently.
- **Known follow-up (out of scope):** the actual client `mcp.json` edit from `http` to `stdio` is a user action, not code; called out in the spec.
