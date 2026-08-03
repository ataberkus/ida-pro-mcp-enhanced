# Multi-Instance IDA MCP Support — Design

**Date:** 2026-08-02
**Status:** Approved (pending user spec review)

## Problem

Today the MCP client connects to a **single** IDA instance:

- The stdio bridge ([bridge_server.py](../../../bridge_server.py)) holds one global `IDA_HOST:IDA_PORT` (default `127.0.0.1:13337`) and proxies every `tools/call` to that one IDA. `--ida-rpc` sets it only at startup.
- Alternatively, a client can connect directly over HTTP/SSE to `http://127.0.0.1:13337/sse` — again a single hardcoded port.

When a second IDA instance runs, the plugin already auto-increments its port (`13338`, `13339`, … up to `+100`) on bind failure, so both servers coexist. But **no component knows the second instance exists**, and the client can only reach the one configured endpoint. There is no discovery, no routing, no instance selection.

### Constraints discovered during brainstorming

- **Ports are unstable.** Auto-increment means the port an IDA lands on says nothing about which IDB it serves; the port↔IDB mapping shuffles every session. Routing must therefore key off **identity** (IDB / input file), never port.
- **Two IDAs starting MCP never collide.** The bind is atomic at the OS level and synchronous in the plugin's `run()`; the loser of a port race gets `OSError` and auto-increments. `allow_reuse_port` is intentionally off, so no silent double-bind.
- **The user's client uses direct HTTP** (`"type": "http", "url": "http://127.0.0.1:13337/sse"`). A direct HTTP connection is owned by the client and cannot do dynamic discovery. Dynamic multi-instance therefore requires the **stdio bridge** as the single endpoint.

## Goals

- One MCP client config entry, no ports, no per-instance entries.
- Open N IDAs → all are discovered automatically; select which one a tool call targets.
- No manual plugin trigger — server starts on IDA load.
- Fully backward compatible: single-IDA workflow unchanged.

## Non-Goals

- Running multiple IDBs inside one IDA process.
- Remote (non-localhost) instances. Discovery is host-local only.
- Auto-selecting by content; selection is explicit (by name) or the single-instance auto-pick.

## Decision Summary (from brainstorming)

| Question | Decision |
|---|---|
| Routing model | Registry discovery + tool-namespacing (target baked into tool name) |
| Endpoint ownership | Independent bridge/router process (not hosted in any IDA) |
| Server startup | Auto-start on IDA database load |
| Transport | stdio bridge (client switches from `http` to `stdio`) |
| Instance handle | `input_file` name → tool-name prefix; registry `id` disambiguates collisions |

## Architecture

```
 MCP client (stdio, one entry, no ports)
        │
        ▼
 ida-pro-mcp bridge  (bridge_server.py — ROUTER, not a single-target proxy)
        │  reads registry dir on every call, probes liveness, routes by name
        ▼
 ┌─────────────┬─────────────┬─────────────┐
 │ IDA #1      │ IDA #2      │ IDA #3      │   each auto-starts its own
 │ :13337      │ :13338      │ :13339      │   MCP_SERVER on auto-incremented port
 └─────────────┴─────────────┴─────────────┘
        │  writes a registry file on serve / removes on stop
        ▼
 %LOCALAPPDATA%\ida-mcp\instances\<id>.json   (Windows)
 ~/.local/share/ida-mcp/instances/<id>.json   (Linux/macOS)
```

No IDA is special. The bridge is the only MCP endpoint; closing any one IDA only removes that instance.

## Component: Plugin-side registry

On `MCP_SERVER.serve()` success in [ida_mcp.py `run()`](../../../ida_mcp.py), the plugin writes one JSON file per instance:

```json
{
  "id": "pid1234-a1b2c3",
  "pid": 1234,
  "host": "127.0.0.1",
  "port": 13337,
  "session_id": "<uuid>",
  "idb_path": "C:/work/crackme.exe.i64",
  "input_file": "crackme.exe",
  "started_at": "2026-08-02T12:00:00Z"
}
```

- **`id`**: unique per process (PID + short random suffix). Used as the registry filename and as a fallback handle when two IDAs open the same file.
- **`input_file` / `idb_path`**: the human/LLM-facing selection handle.
- Written in `run()` after a port binds; **removed in `term()`**.
- A file is treated as **stale** (and ignored) if the PID is dead **or** the port does not answer a `ping`, so a crashed IDA does not linger.

### Auto-start

- `init()` registers a hook: when IDA finishes loading a database, it calls `run()` automatically → binds next free port → writes registry.
- `Ctrl+Alt+M` remains as a manual restart/re-bind escape hatch but is no longer required.

## Component: Bridge router

Replace the single `IDA_HOST/IDA_PORT` global in [bridge_server.py](../../../bridge_server.py) with an instance table built from the registry.

- **`_discover_instances()`** → read registry dir, drop stale entries (dead PID or failed `ping` probe), return live ones.
- **`_post_to_ida(payload, host, port)`** → takes a resolved target instead of using globals.

### Instance targeting: tool-namespacing (chosen)

The target is encoded **in the tool name**, not in a mutable argument or default. The bridge re-exposes each instance's tools under a per-instance prefix derived from `input_file` (sanitized to a valid tool-name token).

- **Exactly one live instance** → its tools are exposed **unprefixed** (`decompile`, `xrefs_to`, …). Backward compatible, zero friction; the single-IDA case is identical to today.
- **Two or more live instances** → each instance's tools are exposed **only** under its prefix: `crackme__decompile`, `library__decompile`, … The unprefixed shared set is **withdrawn**, so there is no ambiguous default to get wrong. The one shared, always-unprefixed tool is `ida_list_instances()`.

Rationale: an LLM mid-task can forget a `use_instance` call or a stale default and silently operate on the wrong IDB. Baking the target into the tool name makes the wrong-IDB failure **impossible by construction** — the agent physically cannot call `decompile` without naming the instance. This matches the upstream project's hard-won rule: *no implicit current database.*

**Sanitization & collisions:** the prefix is `input_file` lowercased, with characters outside `[a-z0-9_]` collapsed to `_` (`crackme.exe` → `crackme_exe`). If two instances sanitize to the same prefix (e.g. the same file opened twice), the bridge appends a short disambiguator from the registry `id` (`crackme_exe_a1b2__decompile`) and surfaces the mapping in `ida_list_instances()`.

**Dynamic tool set:** the set of exposed tools changes as instances come and go. The bridge emits `notifications/tools/list_changed` when discovery detects a change so the client refreshes its tool list. (Rejected alternative: a fixed `instance` argument on a shared tool set — simpler, but reintroduces the mutable-default wrong-IDB risk this design exists to eliminate.)

### Bridge-local tool (answered without touching IDA)

- **`ida_list_instances()`** → `[{id, pid, port, input_file, idb_path, tool_prefix}]`. Always unprefixed. This is how the agent (or user) learns the available prefixes.

### Tool schema cache

The bridge's `_tools_cache` is keyed per-instance and re-exposed under the instance prefix. Schemas are identical across IDAs, so the underlying schema is fetched once per instance and reused; only the exposed `name` (and `title`) is prefixed. The cache invalidates for an instance when it disappears from discovery.

## Error & Edge Handling

- **Instance closes** → its prefixed tools vanish on the next `tools/list` refresh (after `notifications/tools/list_changed`). A call to a now-dead prefix errors with *"instance `crackme_exe` is no longer available; call `ida_list_instances`."* **Never silently remap a prefix to a different IDB.**
- **Two IDAs, same input file** → disambiguated prefixes (`crackme_exe_a1b2__…`), shown in `ida_list_instances()`.
- **Single-IDA** → unprefixed tools; behavior identical to today.
- **Crashed IDA** → stale registry entry dropped on next discovery (dead PID / failed `ping`); its tools disappear.
- **Registry dir unwritable** → bridge falls back to scanning the default port range; each responding `/mcp` becomes an anonymous instance with a port-derived prefix (`ida_13337__…`).

## Client Configuration Change (one-time)

Replace the direct HTTP entry with the stdio bridge:

```jsonc
// before
"ida-pro-mcp": { "type": "http", "url": "http://127.0.0.1:13337/sse" }

// after
"ida-pro-mcp": { "type": "stdio", "command": "ida-pro-mcp" }
```

No ports, no per-instance entries. This is the only config edit; everything else is dynamic.

## Data Flow (typical)

```
agent ──stdio──▶ bridge ──▶ (reads registry, finds 2 IDAs)
                     │
                     ├─▶ 127.0.0.1:13337  (crackme.exe)
                     └─▶ 127.0.0.1:13338  (library.dll)

ida_list_instances()              → [crackme.exe→crackme_exe, library.dll→library_dll]
crackme_exe__decompile("main")    → routed to :13337
library_dll__xrefs_to("Foo")      → routed to :13338
```

With a single IDA the same calls are simply `decompile("main")` / `xrefs_to("Foo")` — unprefixed, identical to today.

## Testing

- **Unit:** `_discover_instances` with fake registry files — live PID, dead PID, stale port, same-file collision.
- **Unit:** prefix sanitization (`crackme.exe` → `crackme_exe`) and collision disambiguation (`crackme_exe_a1b2`).
- **Unit:** tool exposure — 1 instance unprefixed; 2+ instances prefixed and shared set withdrawn.
- **Unit:** `notifications/tools/list_changed` emitted when an instance appears/disappears; dead prefix errors cleanly without remapping.
- **Unit:** `_post_to_ida` routes a prefixed call to the correct (host, port).
- **Regression:** existing single-instance tests pass unchanged.

## Backward Compatibility

- Single-IDA workflow is untouched (auto-select, no new calls needed).
- `--ida-rpc` remains as a legacy single-target override; when set explicitly it bypasses discovery.
- Direct HTTP/SSE transport continues to work for single-instance users who prefer it; multi-instance requires the stdio bridge.
