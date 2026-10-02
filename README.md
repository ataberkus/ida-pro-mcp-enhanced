# IDA Pro MCP Enhanced

> Turn IDA into an agentic reverse-engineering workspace—not just a remote decompiler.

IDA Pro MCP Enhanced is a vNext-first derivative of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp). It gives AI agents a compact, high-leverage interface for navigating binaries, following control and data flow, recovering program structure, building evidence, and safely improving the IDB.

Instead of forcing an agent through hundreds of tiny read calls, vNext combines structured investigation, graph traversal, data-flow tracing, taint analysis, binary recovery, batch operations, and transactional edits behind a bounded 35-tool API. The result is a faster analysis loop, less context waste, and substantially deeper reverse engineering than a one-tool-at-a-time workflow.

## Highlights

- **Investigation, not just lookup.** `analysis_run`, `investigation_start`, `graph_query`, `dataflow_trace`, and `taint_analyze` help an agent reconstruct behavior across whole code paths.
- **Small, strong tool surface.** 35 canonical tools replace legacy tool sprawl. Dead code, duplicate helpers, and superseded tools have been removed.
- **Binary recovery built in.** RTTI class and vtable recovery (MSVC and Itanium), switch/jump-table enumeration, patched-byte listing and diffs, FLIRT signatures, type libraries, and function similarity search.
- **Self-describing tools.** Fixed-choice parameters are advertised as JSON Schema enums and validated; invalid input returns actionable errors that list the allowed values; every tool description follows a WHEN / RETURNS / LIMITS / NEXT format.
- **Fewer round trips.** Batch-first queries, bounded responses, cached strings, and combined analysis results reduce tool-call churn on large databases.
- **Search the analysis, not only the binary.** Deadline-aware listing search finds rendered instructions and analyst comments across selected ranges with resumable cursors.
- **Safe autonomous editing.** Renames, types, comments, patches, and other IDB changes go through preview/commit transactions with revision checks, recovery checkpoints, and rollback.
- **Multiple IDA databases at once.** The stdio bridge discovers live IDA processes and routes each call to the right database.
- **Real safety controls.** Read, annotate, modify, filesystem, debugger, and Python capabilities are independently scoped; non-loopback HTTP requires a bearer token.
- **Headless mode.** `idalib-mcp` serves the same API from idalib, with multiple worker databases and no GUI.
- **IDA 9.4-first runtime.** Current function, segment, decompiler, and microcode APIs are used without the deprecated-call noise found in older integrations.

## Requirements

- **IDA Professional 9.4+ is strongly recommended and is the primary target.** IDA Free is not supported.
- Older IDA releases may work through compatibility fallbacks, but this release is tested and optimized for IDA 9.4+.
- Python 3.11+ and [uv](https://docs.astral.sh/uv/).
- IDAPython must use a Python runtime compatible with the IDA installation. Use `idapyswitch` if IDA reports a libpython mismatch.
- Optional: `analysis_run(mode="emulate")` needs [Unicorn](https://www.unicorn-engine.org/) in IDA's Python (`pip install unicorn`); headless `idalib-mcp` gets it from `uv sync --all-groups` or the `emulate` extra.

## Install

Clone the repository, create the environment, and install the IDA plugin plus an MCP client configuration. This example configures Codex globally over stdio:

```powershell
git clone https://github.com/ataberkus/ida-pro-mcp-enhanced.git
cd ida-pro-mcp-enhanced
uv sync --all-groups
uv run --no-sync ida-pro-mcp --install codex --scope global --transport stdio
```

`--no-sync` is intentional: installation only copies the already-synchronized checkout and avoids replacing a bridge executable that Windows may have open. Completely restart IDA and your MCP client after installation.

Verify the client entry (Codex example):

```powershell
codex mcp get ida-pro-mcp
```

The expected transport is `stdio`, with both `command` and `args` pointing into this checkout. If either path still points to an older clone, remove the stale entry and rerun the installer from the intended checkout.

To remove the plugin and client entries, run `uv run --no-sync ida-pro-mcp --uninstall [targets]`.

### Update an existing installation

Fully quit your MCP clients before synchronizing so Windows releases the bridge executable:

```powershell
cd path\to\ida-pro-mcp-enhanced
git pull --ff-only
uv sync --all-groups
uv run --no-sync ida-pro-mcp --install codex --scope global --transport stdio
```

Then restart IDA and the client. Running the installer again safely refreshes the loader, plugin package, vNext support package, and client configuration.

If `uv` reports `failed to remove ... Scripts/ida-pro-mcp.exe: Access denied`, a client/bridge process still has the executable open. Either fully quit the client before rerunning `uv sync`, or refresh the plugin immediately without environment synchronization:

```powershell
uv run --no-sync ida-pro-mcp --install codex --scope global --transport stdio
```

Do not delete `.venv` while its bridge is running.

If IDA was launched from a Python virtual-environment terminal, inherited variables can make IDAPython select the wrong runtime. On Windows, use the included clean launcher:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_ida_clean.ps1
```

## MCP client configuration

When run by a client, the bridge serves MCP over **stdio**. This is the recommended transport because it enables multi-instance discovery and routing. The installer writes the configuration for you:

```powershell
uv run --no-sync ida-pro-mcp --install <client> --scope <global|project> --transport stdio
```

- `--install <client>` accepts comma-separated targets (e.g. `claude,cursor`); without targets it shows an interactive selector.
- `--scope global` writes a user-level config; `--scope project` (the non-interactive default) writes one inside the current directory.
- `--transport` selects `stdio` (default), `streamable-http`, or `sse`. The interactive installer pre-selects the transport already present in your client config.
- `--config` prints the raw JSON for the current setup; `--list-clients` lists every supported target.

The examples below show manual configuration for common clients. All paths must be **absolute**. Replace `C:\path\to\ida-pro-mcp-enhanced` with the location of your checkout, and do not mix the bridge from one clone with plugin files from another.

### VS Code

VS Code reads MCP servers from a top-level `"servers"` object in either `.vscode/mcp.json` (project) or `%APPDATA%\Code\User\mcp.json` (user):

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

### Claude Desktop, Claude Code, and Cursor

These clients use a top-level `"mcpServers"` object:

- **Claude Desktop:** `%APPDATA%\Claude\claude_desktop_config.json`. Fully quit and restart Claude Desktop after saving.
- **Claude Code:** `.mcp.json` in the workspace root (project) or `~/.claude.json` (user).
- **Cursor:** `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (user).

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

Codex stores global MCP servers in `%USERPROFILE%\.codex\config.toml` on Windows (`~/.codex/config.toml` elsewhere); project entries may use `.codex/config.toml`:

```toml
[mcp_servers.ida-pro-mcp]
command = "C:\\path\\to\\ida-pro-mcp-enhanced\\.venv\\Scripts\\python.exe"
args = ["C:\\path\\to\\ida-pro-mcp-enhanced\\src\\ida_pro_mcp\\bridge_server.py"]
```

Or from the CLI:

```powershell
codex mcp add ida-pro-mcp -- "C:\path\to\ida-pro-mcp-enhanced\.venv\Scripts\python.exe" "C:\path\to\ida-pro-mcp-enhanced\src\ida_pro_mcp\bridge_server.py"
```

Verify with `codex mcp get ida-pro-mcp` or `codex mcp list`.

### Other clients and transports

The installer also configures Cline, Roo Code, Kilo Code, Windsurf, Zed, Kimi Code, Gemini CLI, Qwen Coder, Copilot CLI, LM Studio, Amazon Q, and more. Run `uv run --no-sync ida-pro-mcp --list-clients` for the full list.

For remote or headless setups, the bridge can also serve **streamable HTTP** or **SSE**. Its listener must use a different port from the IDA plugin, which uses `13337` by default. This example uses `8744`:

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

Binding to a non-loopback address requires a bearer token. Create one with `uv run --no-sync ida-pro-mcp auth init` (written to `%APPDATA%\ida-pro-mcp\auth-token` on Windows, `~/.config/ida-pro-mcp/auth-token` elsewhere), then pass `--auth-token-file <path>` or set `IDA_MCP_AUTH_TOKEN`.

> **Note:** Connecting directly to IDA at `http://127.0.0.1:13337/mcp` reaches only that IDA process and bypasses multi-instance discovery. Prefer the stdio bridge when you run more than one database.

## Tool reference

The advertised vNext API is deliberately focused. All 35 canonical tools:

| Area | Tools |
| --- | --- |
| Server and databases | `server_capabilities`, `idb_open`, `idb_list`, `idb_save`, `idb_close` |
| Lookup and evidence | `entity_query`, `search`, `memory_read`, `disassemble`, `decompile`, `type_query`, `int_convert`, `signature_create` |
| Analysis | `analysis_run`, `graph_query`, `dataflow_trace`, `taint_analyze` |
| Background jobs | `job_status`, `job_cancel`, `job_result` |
| Investigations | `investigation_start`, `investigation_get`, `investigation_add_finding`, `investigation_export` |
| IDB mutation | `mutation_preview`, `mutation_commit`, `mutation_status`, `mutation_rollback` |
| Debugger (opt-in) | `debug_session`, `debug_control`, `debug_breakpoints`, `debug_state`, `debug_memory`, `debug_trace` |
| Python (opt-in) | `python_execute` |

`idb_open`, `idb_list`, and `idb_close` manage sessions in headless `idalib-mcp`; in the GUI plugin the open database is used directly.

What the main tools do:

- **`analysis_run`** modes: `triage` (ranks interesting functions with reasons such as `calls:crypto` or `refs:strings`, plus interesting strings and imports by category; `detail_level="full"` widens the lists), `function` (prototype, a 120-line decompile excerpt with `next_line_offset`, strings, constants, callers, callees, references, and blocks; disassembly, comments, and declarations are opt-in), `component` and `batch` (several targets; `batch` returns only `options.sections`, by default decompile, callees, and strings), `similar` (ranks functions by mnemonic 3-gram similarity and lists each match's callee count and strings), `emulate` (runs a function under Unicorn once per `options.calls` argument list, with ints, names, or `{bytes|string|wstring|buffer}` heap arguments, and reports its return value, return string, stubbed import calls, and decoded memory writes, with a warning for every unmodelled import that returned 0; useful for string decryptors and API-hash resolvers), and `deep` (a cancellable background job that adds data-flow traces).
- **`decompile`** pages pseudocode with `line_offset`/`line_limit` (default 400 lines) and reports `total_lines` and `next_line_offset`; a trailing `/*0xEA*/` marker maps each line to its instruction. Unknown names come back with near-miss suggestions.
- **`entity_query`** lists `functions`, `globals`, `imports`, `strings`, `names`, `segments`, `entrypoints`, and per-function `locals`, plus recovered `switches`, `patches`, `classes`/`vtables` (RTTI), available FLIRT `signatures`, and `type_libraries`, with glob/regex filtering, projection, sorting, and pagination; `include_counts=true` adds `xref_count` and enables `sort_by="xref_count"`.
- **`graph_query`** explores `xrefs`, `xrefs_from`, and `xrefs_both` (filterable by `options.xref_type` code/data), paged breadth-first `calls` and `callers` graphs (indirect call sites and address-taken references listed per node), shortest call `path` between two functions, `field_xrefs` for a `Struct.field`, and `cfg` blocks; `callsite_args` lists every decompiled call to a function or import with each argument's constant value, address, or string.
- **`dataflow_trace`** follows values `forward`, `backward`, or `both` from an address, a function's parameters, or a `func:var` variable, returning pseudocode statements with variable-name defines/uses; **`taint_analyze`** finds source-to-sink paths (`main:argv` → `printf`, API results → calls) across direct calls into callees (at most 20 functions), with readable steps and a heuristic confidence; `options.domains` limits propagation to register, stack, global, or memory locations.
- **`search`** finds `text`, `regex`, `bytes`, `constant`, and `instruction` matches with per-target resumable cursors. Text and regex cover disassembly and comments (`options.include="strings"` for string literals) and accept `case_sensitive`, `code_only`, `func`, `segment`, and `start`/`end` options; constants match any operand width; instruction patterns read like `cmp op1=6` or `* any=0x5A4D`. `crypto` finds known crypto, hash, CRC, compression, and API-hash constants as data tables or code immediates; `ctree` matches decompiled code with patterns such as `callee=memcpy arg2=!const`, `op=cmp value=0x5A4D`, or `op=num value=0x9E3779B9 in=^sub_`.
- **`memory_read`** reads `bytes`, `integer`, `string`, `global`, and typed `struct` values. Addresses accept hex, names, `name+0x10`, and `segment:addr`; integer queries accept an `addr:ty` shorthand such as `main+0x10:u32`; sizes default to the item size. Kind `patch_diff` reports every patched byte range.
- **`type_query`** inspects structs, unions, enums, typedefs, function types, and pointers; `kind="inferred"` reports an address's applied type, Hex-Rays prototype, or IDA's guess before `set_type`.
- **`signature_create`** produces byte signatures in `ida`, `x64dbg`, `mask`, or `bitmask` format.
- **`job_status`** with `wait_sec` (up to 30 s) blocks until a background job ends, replacing polling loops.
- **`investigation_*`** keeps an evidence-driven record of findings and exports it as `json`, `markdown`, or `sarif`. Evidence accepts `addr` or `address`; `apply_to_idb=true` bookmarks every evidence address in one undoable commit. `investigation_start` budgets cap analyzed seeds (`max_seeds`, default 20) and can `skip_triage`.
- **`python_execute`** runs an expression (`eval`) or a workspace-restricted script (`file`) when the Python scope is enabled.

MCP resources are also exposed: `ida://idb/metadata`, `ida://idb/entrypoints`, `ida://cursor`, and `ida://selection`.

### Transactional mutation

Every IDB change is staged with `mutation_preview`, which resolves addresses, parses types and declarations, records the before-state of each operation, and rejects an invalid operation by index. `mutation_commit` then applies the batch atomically. A batch made only of annotate-scope kinds (renames, comments, bookmarks, types, enums, operand display, stack variables) can pass `commit=true` to preview and commit in one call. Supported operation kinds:

`rename`, `comment`, `append_comment`, `bookmark`, `declare_type`, `set_type`, `upsert_enum`, `set_operand_type`, `declare_stack`, `delete_stack`, `patch_bytes`, `write_integer`, `patch_asm`, `define_function`, `define_code`, `undefine`, `make_data`, `apply_flirt`, `load_til`, `save_database`.

Operations take flat fields, such as `{"kind": "rename", "addr": "sub_401000", "name": "parse_header"}`, or an `items` batch. A `__noreturn` prototype in `set_type` marks a function no-return. `define_function` with `end` resizes an existing function. `set_operand_type` with `operand_kind="enum"` shows an operand as an enum member. Appended line comments also appear in pseudocode.

Each preview expires and is tied to an IDB revision. If a target changes before commit, the operation fails with `STALE_REVISION` instead of silently applying an outdated plan. Commits refresh cached decompilations and can be undone with `mutation_rollback`.

## Safety profiles

New installations default to the **Modify** profile: read, annotation, and IDB mutation are enabled, while debugger, filesystem, and Python access remain opt-in. The Annotate profile can commit and roll back annotate-only transactions; byte and code edits need Modify.

With IDA running, open [http://127.0.0.1:13337/config.html](http://127.0.0.1:13337/config.html) to switch between Read only, Annotate, and Modify. Profile files in [`profiles/`](profiles/) (`readonly`, `triage`, `annotate`, `modify`, `canonical`, `debug`, `python`, `legacy`) restrict the tool list further, for example with `idalib-mcp --profile profiles/triage.txt`.

## Multi-instance routing

The stdio bridge discovers every running IDA instance:

- With one IDA instance, tools keep their normal unprefixed names.
- With multiple instances, tools become `<database_prefix>__<tool>`.
- `ida_list_instances` reports live processes, database paths, and routing prefixes.
- Databases with colliding names receive an instance-derived disambiguator.
- Closing or crashing IDA invalidates the stale routing target during discovery refresh.

## Headless mode (idalib)

`idalib-mcp` serves the API without the IDA GUI, using idalib worker processes:

```powershell
uv run --no-sync idalib-mcp --stdio path\to\binary
uv run --no-sync idalib-mcp --host 127.0.0.1 --port 8745 path\to\binary
```

- The binary argument is optional; open more databases later with `idb_open` and list them with `idb_list`.
- `--max-workers` caps simultaneous worker databases (default 4, `0` = unlimited).
- `--safety-scope` enables a scope (repeatable), `--profile` restricts tools to a profile file, and `--workspace-root` restricts binary and output paths (repeatable).
- Non-loopback HTTP requires `--auth-token-file` or `IDA_MCP_AUTH_TOKEN`.
- `idb_open` waits for auto-analysis up to `IDA_MCP_OPEN_WAIT_SEC` (default 90 s) and then returns `state="opening"` while analysis continues; `wait=false` returns immediately. Calls to a database that is still analyzing fail fast with the elapsed time; poll `idb_list`.
- Worker tools take an optional `database`: a session id or prefix, filename, or path from `idb_list`. Omit it when one database is open.
- Oversized results are truncated with a hint to narrow the request (paging, `line_offset`/`line_limit`, `fields`); no download URL is offered.
- Background jobs reach IDA through a main-thread queue that the server drains every 20 ms, so `analysis_run(mode="deep")` and investigations complete headlessly.

## Troubleshooting

If `tools/list` works but `entity_query`, `search`, or other IDA-backed calls time out:

1. Confirm the client's stdio paths point to the intended checkout (for Codex, `codex mcp get ida-pro-mcp`).
2. From that checkout, run `uv sync --all-groups` followed by the `--install` command above.
3. Completely restart IDA so it loads the refreshed plugin package, then restart the MCP client so it launches the refreshed bridge.
4. Inspect `%TEMP%\ida_pro_enhanced_logs\ida-pro-mcp-sync-<ida-pid>.log`. Each request records its ID, worker/UI thread, queue delay, execution time, scheduler, outcome, and exception traceback. `queue_start_timeout` means IDA's Qt event loop never dispatched the posted event; `ui_started` followed by no `ui_finished` identifies a tool that stalled after dispatch; `ui_event_deferred` means a nested Qt delivery was safely queued behind an active IDA call; and `ui_finished` should be followed by `ui_turn_released` on a later Qt turn.

The same directory contains `ida-pro-mcp-errors-<ida-pid>.log`, a smaller error-only stream for queue failures, exceptions, structured tool errors, decompiler failures, and call-stack inconsistencies. Returned failures are logged as `tool_reported_error`; decompiler failures also emit `decompile_failed` with the resolved function, Hex-Rays error code and description, and failure address, and the `decompile` response suggests a `disassemble` fallback.

For argument-level history, export the trace embedded in a closed IDB with `uv run --no-sync ida-mcp-trace-dump <database.i64> --output <trace.jsonl>`. The reader is idalib-only and does not load the GUI plugin or PySide6.

The plugin and bridge are separate runtime halves; updating only the client configuration or only the copied IDA plugin can leave an older implementation active.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `IDA_MCP_SYNC_QUEUE_TIMEOUT_SEC` | UI-thread start timeout (default 10 s) |
| `IDA_MCP_SYNC_LOG`, `IDA_MCP_ERROR_LOG` | Override the diagnostic log paths |
| `IDA_MCP_SEARCH_PAGE_BUDGET_SEC` | Listing-search page budget (default 5 s, max 20 s) |
| `IDA_MCP_CONTENDED_SEARCH_PAGE_BUDGET_SEC` | Page budget under `queue_pressure` (default 250 ms, max 1 s) |
| `IDA_MCP_AUTH_TOKEN` | Bearer token for non-loopback HTTP |
| `IDA_MCP_OPEN_WAIT_SEC` | `idb_open` wait before returning `state="opening"` (default 90 s, `0` waits for analysis) |

## Development

```powershell
uv sync --all-groups
uv run --no-sync pytest tests -q -p no:cacheprovider
uv run --no-sync pytest tests_bridge -q -p no:cacheprovider
uv run --no-sync ruff check src/ida_pro_mcp/vnext src/ida_pro_mcp/ida_mcp/api_vnext.py src/ida_pro_mcp/ida_mcp/hexrays_dataflow.py src/ida_pro_mcp/ida_mcp/rpc.py src/ida_pro_mcp/idalib_supervisor.py
uv build
```

IDA-backed API tests run headlessly through idalib against the maintained fixtures:

```powershell
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
```

CI runs the portable suite on Windows, Linux, and macOS, plus the lint job and the idalib fixture tests.

The vNext contract is documented in [`devdocs/vnext.md`](devdocs/vnext.md), the test framework in [`devdocs/test-framework.md`](devdocs/test-framework.md), and multi-instance design notes under [`devdocs/multi-instance/`](devdocs/multi-instance/).

### Verification status

Current Windows/IDA 9.4 checks:

- Portable suite: **358 passed, 116 subtests passed**.
- Multi-instance bridge suite: **24 passed**.
- idalib fixture suites: `crackme03.elf` **307 passed, 1 skipped**; `typed_fixture.elf` **267 passed, 1 skipped**.
- Live `idalib-mcp --stdio` smoke on `crackme03.elf` and `notepad.exe`: paged decompilation, triage, search, call graphs, taint, transactional commit/rollback, and deep jobs.
- Live IDA 9.4 registration, resource reads, tool listing, function analysis, transactional mutation, and IDB save have been exercised.
- Multi-instance routing is unit verified; two-GUI live acceptance is pending.

## Upstream and license

This repository preserves the upstream Git history and is based on upstream commit `f82e6e2` of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp), with full attribution retained.

License: [MIT](LICENSE)
