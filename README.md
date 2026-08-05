# IDA Pro MCP Enhanced

> Turn IDA into an agentic reverse-engineering workspace—not just a remote decompiler.

IDA Pro MCP Enhanced is a vNext-first derivative of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp). It gives AI agents a compact, high-leverage interface for navigating binaries, following control and data flow, building evidence, and safely improving the IDB.

Instead of forcing an agent through hundreds of tiny read calls, vNext combines structured investigation, graph traversal, data-flow tracing, taint analysis, batch operations, and transactional edits. The result is a faster analysis loop, less context waste, and substantially deeper reverse engineering than the legacy one-tool-at-a-time workflow.

## Why it feels different

- **Investigation, not just lookup.** `analysis_run`, `investigation_start`, `graph_query`, `dataflow_trace`, and `taint_analyze` help an agent reconstruct behavior across whole code paths.
- **Smaller and stronger tool surface.** A bounded 35-tool canonical API replaces legacy tool sprawl while retaining proven implementations internally.
- **Fewer round trips.** Batch-first queries, bounded responses, cached strings, and combined analysis results reduce tool-call churn on large databases.
- **Search the analysis, not only the binary.** Deadline-aware listing search finds rendered instructions and analyst comments across selected ranges with resumable cursors.
- **Safe autonomous editing.** Renames, types, comments, and other IDB changes use preview/commit transactions, revision checks, recovery checkpoints, and rollback support.
- **Sharper IDB refinement.** Agents can add bookmarks, set operand display and structure-offset types, and create typed data through the transactional mutation path.
- **Multiple IDA databases at once.** The stdio bridge discovers live IDA processes and routes each call to the right database.
- **Real safety controls.** Read, annotate, modify, debugger, filesystem, and Python capabilities are independently scoped.
- **IDA 9.4-first runtime.** Current function, segment, decompiler, and microcode APIs are used without the deprecated-call noise found in older integrations.

## Requirements

- **IDA Professional 9.4+ is strongly recommended and is the primary target.** IDA Free is not supported.
- Older IDA releases may work through compatibility fallbacks, but this enhanced release is tested and optimized for IDA 9.4+.
- Python 3.11+ and [uv](https://docs.astral.sh/uv/) for the standalone bridge.
- IDAPython must be pinned to a Python runtime compatible with the IDA installation. Use `idapyswitch` if IDA reports a libpython mismatch.

## Install

Clone the private repository, create the bridge environment, and install the IDA plugin plus global Codex stdio configuration:

```powershell
git clone https://github.com/ataberkus/ida-pro-mcp-enhanced.git
cd ida-pro-mcp-enhanced
uv sync --all-groups
uv run --no-sync ida-pro-mcp --install codex --scope global --transport stdio
```

`--no-sync` is intentional: installation only copies the already-synchronized checkout and avoids replacing a bridge executable that Windows may have open. Completely restart IDA and Codex after installation.

Verify the global client entry:

```powershell
codex mcp get ida-pro-mcp
```

The expected transport is `stdio`, with both `command` and `args` pointing into this checkout. If either path still points to an older clone, remove the stale entry and rerun the installer from the intended checkout.

### Update an existing installation

Fully quit Codex and other MCP clients before synchronizing so Windows releases the bridge executable:

```powershell
cd path\to\ida-pro-mcp-enhanced
git pull --ff-only
uv sync --all-groups
uv run --no-sync ida-pro-mcp --install codex --scope global --transport stdio
```

Then restart IDA and Codex. Running the installer again safely refreshes the loader, plugin package, vNext support package, and Codex configuration.

If `uv` reports `failed to remove ... Scripts/ida-pro-mcp.exe: Access denied`, a Codex/bridge process still has the executable open. Either fully quit Codex before rerunning `uv sync`, or refresh the plugin immediately without environment synchronization:

```powershell
uv run --no-sync ida-pro-mcp --install codex --scope global --transport stdio
```

Do not delete `.venv` while its bridge is running.

If IDA was launched from a Python virtual-environment terminal, inherited variables can make IDAPython select the wrong runtime. On Windows, use the included clean launcher:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_ida_clean.ps1
```

## MCP client configuration

The bridge runs on **stdio** by default, which is the recommended transport because it enables multi-instance discovery and routing. The installer can write the correct configuration for you:

```powershell
uv run --no-sync ida-pro-mcp --install <client> --scope <global|project> --transport stdio
```

- `--install <client>` accepts comma-separated targets (e.g. `claude,cursor`) or an interactive selector when omitted.
- `--scope global` writes a user-level config; `--scope project` writes a config inside the current project.
- `--transport` selects `stdio` (default), `streamable-http`, or `sse`.
- `--config` prints the raw JSON for the current setup; `--list-clients` lists every supported target.

The examples below show manual configuration for the most common clients. All paths must be **absolute**. Replace `C:\path\to\ida-pro-mcp-enhanced` with the location of your checkout; do not mix the bridge from one clone with plugin files from another.

### VS Code

VS Code reads MCP servers from a top-level `"servers"` object. Add the entry to either:

- **Project scope** — `.vscode/mcp.json` in your workspace root.
- **User scope** — `%APPDATA%\Code\User\mcp.json` (global, applies to every workspace).

```jsonc
{
  "servers": {
    "ida-pro-mcp": {
      "command": "C:\\path\\to\\ida-pro-mcp-enhanced\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\path\\to\\ida-pro-mcp-enhanced\\src\\ida_pro_mcp\\bridge_server.py"
      ]
    }
  }
}
```

> **Note:** When configuring through VS Code `settings.json` instead of `mcp.json`, the servers live under an extra `"mcp"` key: `{ "mcp": { "servers": { ... } } }`.

### Claude Desktop

Claude Desktop reads from `%APPDATA%\Claude\claude_desktop_config.json` using a top-level `"mcpServers"` object:

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "C:\\path\\to\\ida-pro-mcp-enhanced\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\path\\to\\ida-pro-mcp-enhanced\\src\\ida_pro_mcp\\bridge_server.py"
      ]
    }
  }
}
```

Fully quit and restart Claude Desktop after saving so it launches the server.

### Claude Code

Claude Code reads project-scoped servers from `.mcp.json` in the workspace root (or from `~/.claude.json` for user scope), using a top-level `"mcpServers"` object:

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "C:\\path\\to\\ida-pro-mcp-enhanced\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\path\\to\\ida-pro-mcp-enhanced\\src\\ida_pro_mcp\\bridge_server.py"
      ]
    }
  }
}
```

### Codex

Codex stores global MCP servers in `%USERPROFILE%\.codex\config.toml` on Windows (`~/.codex/config.toml` on other platforms). Project-scoped entries may instead use `.codex/config.toml`. For the recommended global stdio configuration:

```toml
[mcp_servers.ida-pro-mcp]
command = "C:\\path\\to\\ida-pro-mcp-enhanced\\.venv\\Scripts\\python.exe"
args = ["C:\\path\\to\\ida-pro-mcp-enhanced\\src\\ida_pro_mcp\\bridge_server.py"]
```

You can also add it from the CLI:

```powershell
codex mcp add ida-pro-mcp -- "C:\path\to\ida-pro-mcp-enhanced\.venv\Scripts\python.exe" "C:\path\to\ida-pro-mcp-enhanced\src\ida_pro_mcp\bridge_server.py"
```

Verify with `codex mcp get ida-pro-mcp` or `codex mcp list`.

### Cursor

Cursor reads project-scoped servers from `.cursor/mcp.json` (or `~/.cursor/mcp.json` for user scope), using a top-level `"mcpServers"` object:

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "C:\\path\\to\\ida-pro-mcp-enhanced\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\path\\to\\ida-pro-mcp-enhanced\\src\\ida_pro_mcp\\bridge_server.py"
      ]
    }
  }
}
```

### Other clients and transports

The installer also knows how to configure Cline, Roo Code, Kilo Code, Windsurf, Zed, Kimi Code, Gemini CLI, Qwen Coder, Copilot CLI, LM Studio, Amazon Q, and more — run `uv run --no-sync ida-pro-mcp --list-clients` to see the full list.

For remote or headless setups, the bridge can also be reached over **streamable HTTP** or **SSE** instead of stdio. Its listener must use a different port from the IDA plugin, which uses `13337` by default. This example uses `8744`:

```powershell
uv run --no-sync ida-pro-mcp --transport http://127.0.0.1:8744/mcp
```

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:8744/mcp"
    }
  }
}
```

> **Note:** Connecting directly to IDA at `http://127.0.0.1:13337/mcp` reaches only that IDA process and bypasses multi-instance discovery. Prefer the stdio bridge when you run more than one database.

### Installation troubleshooting

If `tools/list` works but `entity_query`, `search`, or other IDA-backed calls time out:

1. Run `codex mcp get ida-pro-mcp` and confirm both stdio paths point to the intended checkout.
2. From that checkout, run `uv sync --all-groups` followed by `uv run --no-sync ida-pro-mcp --install codex --scope global --transport stdio`.
3. Completely restart IDA so it loads the refreshed plugin package, then restart the MCP client so it launches the refreshed bridge.
4. Inspect `%TEMP%\ida_pro_enhanced_logs\ida-pro-mcp-sync-<ida-pid>.log`. Each request records its ID, worker/UI thread, queue delay, execution time, scheduler, outcome, and exception traceback. `queue_start_timeout` means IDA's Qt event loop never dispatched the posted event; `ui_started` followed by no `ui_finished` identifies a tool that stalled after dispatch; `ui_event_deferred` means a nested Qt delivery was safely queued behind an active IDA call; and `ui_finished` should be followed by `ui_turn_released` on a later Qt turn.

The same directory contains `ida-pro-mcp-errors-<ida-pid>.log`, a smaller error-only stream for queue failures, exceptions, structured tool errors, decompiler failures, and call-stack inconsistencies. The UI-start timeout defaults to 10 seconds and can be overridden with `IDA_MCP_SYNC_QUEUE_TIMEOUT_SEC`. Override the files with `IDA_MCP_SYNC_LOG` and `IDA_MCP_ERROR_LOG`.

Returned failures are logged as `tool_reported_error` with outcome `reported_error`, rather than being mistaken for successful calls. Decompiler failures additionally emit `decompile_failed` with the input and resolved function addresses, function name, Hex-Rays error code/name and description, exact failure address when supplied by Hex-Rays, exception details, and the diagnostic-log path. The `decompile` response carries the same bounded details plus a `disassemble` fallback target.

For argument-level history, export the trace embedded in a closed IDB with `uv run --no-sync ida-mcp-trace-dump <database.i64> --output <trace.jsonl>`. The reader is IDALib-only and does not load the GUI plugin or PySide6. Structured errors include safe context fields such as the original input, resolved address, and reason; Python execution exceptions include an explicit `error` field alongside captured stdout/stderr.

Rendered-listing text search uses five-second pages and returns a continuation cursor before common MCP client timeouts. Override the page budget with `IDA_MCP_SEARCH_PAGE_BUDGET_SEC`; values are capped at 20 seconds.

The plugin and bridge are separate runtime halves; updating only the client configuration or only the copied IDA plugin can leave an older implementation active.

## Agentic analysis surface

The advertised vNext API is deliberately focused:

- `analysis_run` collects decompilation, disassembly, references, strings, constants, callees, callers, blocks, and risk signals in one bounded result.
- `investigation_start` and `investigation_get` maintain an evidence-driven investigation instead of losing findings between calls.
- `graph_query` explores callers, callees, paths, neighborhoods, and cross-reference relationships.
- `dataflow_trace` follows values forward or backward from an address or a symbol such as `main`.
- `taint_analyze` traces source-to-sink influence with explicit bounds.
- `decompile`, `disassemble`, `search`, `memory_read`, and `type_query` provide targeted evidence when deeper inspection is needed.
- `search` now covers rendered disassembly and comments, while `memory_read` accepts agent-friendly address forms and produces bounded results.
- Opt-in debugger and Python scopes include debugger-state inspection and execution of workspace-restricted analysis scripts.
- Mutation tools preview a batch, validate the active database revision, create a checkpoint, and then commit atomically.

Legacy tools are currently hidden from MCP clients so the vNext interface can be tested as a complete workflow. Their implementations remain available internally where vNext orchestration depends on them.

## Safety profiles

New installations default to the **Modify** profile: read, annotation, and IDB mutation are enabled, while debugger, filesystem, and arbitrary Python access remain opt-in.

With IDA running, open [http://127.0.0.1:13337/config.html](http://127.0.0.1:13337/config.html) to switch quickly between Read only, Annotate, and Modify. Additional canonical, debug, Python, and legacy profiles live in [`profiles/`](profiles/).

Every mutation preview expires and is tied to an IDB revision. If the database changes before commit, the operation fails with `STALE_REVISION` instead of silently applying an outdated plan.

## Multi-instance routing

The stdio bridge is the recommended transport:

- With one IDA instance, tools retain normal unprefixed names.
- With multiple instances, tools become `<database_prefix>__<tool>`.
- `ida_list_instances` reports live processes, database paths, and routing prefixes.
- Databases with colliding names receive an instance-derived disambiguator.
- Closing or crashing IDA invalidates the stale routing target during discovery refresh.

A direct connection to `http://127.0.0.1:13337/mcp` still works, but it connects to only that single IDA process and bypasses multi-instance discovery.

## Verification status

Current Windows/IDA 9.4 release checks:

- Portable suite: **243 passed, 114 subtests passed**.
- Multi-instance bridge suite: **17 passed**.
- Targeted Ruff checks, `compileall`, package build, isolated installation, and CLI smoke pass.
- Live IDA 9.4 registration, resource reads, tool listing, function analysis, transactional mutation, and IDB save have been exercised.
- The thread-safe Qt posted-event scheduler and immediate request chaining are live verified in IDA 9.4; search-page budgeting and late-callback abandonment are regression tested.
- Multi-instance routing is unit verified; final two-GUI live acceptance remains pending.

## Development

```powershell
uv sync --all-groups
uv run --no-sync pytest tests -q -p no:cacheprovider
uv run --no-sync pytest tests_bridge -q -p no:cacheprovider
uv run --no-sync ruff check src/ida_pro_mcp/ida_mcp/api_core.py src/ida_pro_mcp/ida_mcp/api_survey.py src/ida_pro_mcp/ida_mcp/compat.py src/ida_pro_mcp/ida_mcp/hexrays_dataflow.py
uv build
```

The vNext contract is documented in [`devdocs/vnext.md`](devdocs/vnext.md). Multi-instance design and acceptance notes are under [`devdocs/multi-instance/`](devdocs/multi-instance/).

## Upstream and license

This repository preserves the upstream Git history and is based on upstream commit `f82e6e2`. It is maintained as a standalone private derivative so enhanced development can remain private while retaining clear attribution.

Upstream: [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

License: [MIT](LICENSE)
