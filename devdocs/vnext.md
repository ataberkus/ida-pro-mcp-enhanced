# IDA Pro MCP vNext

vNext exposes a shared, versioned contract from both the in-IDA plugin and the
`idalib-mcp` supervisor. The default profile contains the canonical analysis
and IDB mutation tools with `read`, `annotate`, and `modify` scopes. Filesystem,
debugger, and Python scopes remain opt-in. Legacy implementations remain
registered for internal orchestration, but this test branch does not advertise
them to external MCP clients.

The in-IDA page at `http://127.0.0.1:13337/config.html` provides Read only,
Annotate, and Modify quick profile buttons. Modify enables IDB mutation scopes;
filesystem, debugger, and Python scopes remain disabled until explicitly enabled.
This branch runs in vNext-only test mode: legacy implementations remain
available to internal orchestration but are hidden from `tools/list` and direct
legacy tool calls.

## Safety and transport

Safety is expressed as scopes: `read`, `annotate`, `modify`, `filesystem`,
`debug`, and `python`. New installations receive `read`, `annotate`, and
`modify`. A tool call is
authorized against its declared scopes before IDA dispatch, and the MCP schema
includes standard read-only, destructive, idempotent, and open-world
annotations plus `ida_mcp` capability metadata.

HTTP bound beyond loopback fails closed without a bearer token. Run
`ida-pro-mcp auth init`, pass the resulting file with `--auth-token-file`, and
send the token only in the `Authorization: Bearer ...` header. URL tokens are
not supported. Supervisor-to-worker calls use a different, ephemeral token.
Configured workspace roots are canonicalized before file open, save, execute,
or export, preventing traversal and symlink escapes.

The transport rejects disallowed browser origins before reading request
bodies, enforces limits after gzip/deflate expansion, scopes cancellation by
transport session, bounds concurrent stdio dispatch, and keeps protocol logs
on stderr. Audit records are local and redact authorization, tokens, Python
source, and sensitive arguments. There is no telemetry.

## Canonical tools

- Sessions: `server_capabilities`, `idb_open`, `idb_list`, `idb_save`, `idb_close`
- Queries: `entity_query`, `search`, `memory_read`, `disassemble`, `decompile`, `type_query`, `int_convert`, `signature_create`
- Analysis: `analysis_run`, `graph_query`, `dataflow_trace`, `taint_analyze`
- Jobs and investigations: `job_status`, `job_cancel`, `job_result`, `investigation_start`, `investigation_get`, `investigation_add_finding`, `investigation_export`
- Mutations: `mutation_preview`, `mutation_commit`, `mutation_status`, `mutation_rollback`
- Debugger: `debug_session`, `debug_control`, `debug_breakpoints`, `debug_state`, `debug_memory`, `debug_trace`
- Restricted execution: `python_execute`

Canonical collections return a versioned envelope with `data`, `warnings`,
`provenance`, `truncated`, and `next_cursor`. Addresses are hexadecimal strings.
Stable failures include `PROFILE_DENIED`, `AUTH_REQUIRED`, `NOT_SUPPORTED`,
`STALE_REVISION`, `INVALID_DATABASE`, `JOB_INTERRUPTED`, `LIMIT_EXCEEDED`, and
`REOPEN_REQUIRED`.

## Mutations and recovery

`mutation_preview` validates a complete discriminated operation batch and
records required scopes, affected arguments, revision, expiry, and estimated
checkpoint size without changing the IDB. `mutation_commit` accepts only that
preview identifier, rechecks database/revision/scopes, writes an external
recovery IDB to the platform cache only when the dashboard Recovery-checkpoints
option is enabled (off by default), and applies operations through the existing
main-thread-safe IDA functions. When checkpoints are disabled the receipt
checkpoint is null and rollback relies on native undo; otherwise it raises
REOPEN_REQUIRED. IDB hooks cover names, comments, bookmarks,
bytes, code/data, functions, types, stack members, and segments so out-of-band
edits invalidate previews and caches.

Rollback uses native undo when available. Otherwise the checkpoint is returned
with `REOPEN_REQUIRED`; a live database is never described as atomically
restored when it was not. Debug-memory writes require `debug` and
`confirm_nonrollbackable=true`; Python requires its isolated scope.

`idb_open`, `idb_list`, and `idb_close` are supervisor-only canonical tools.
`entity_query`, `decompile`, `type_query`, `int_convert`, and `idb_save` are
canonical legacy tools in both runtimes.

## Jobs, investigations, and analysis

Long analyses run as bounded jobs with progress and cooperative cancellation.
Job and investigation records persist in namespaced IDB netnodes. A queued or
running record found after restart becomes `interrupted`; completed findings
and evidence remain exportable as deterministic JSON, Markdown, SARIF, DOT, or
Mermaid. Job and investigation resources support subscription updates with
event coalescing.

When Hex-Rays can generate microcode, `dataflow_trace` builds instruction
definition/use location lists and computes reaching definitions across the
function CFG. Results identify the `hexrays_microcode` engine, evidence, and
unsupported edge categories. Without Hex-Rays, the existing traversal is
returned as `reference_flow` and is never labeled semantic. `taint_analyze`
uses those edges, stops at configured sanitizers, tracks location domains, and
assigns engine-dependent confidence.

Supervisor `analysis_run(mode="binary_diff")` accepts the left session as
`database` and the other session as `options.right_database`. It matches
functions using non-generated symbols, wildcarded IDA signatures, normalized
instruction hashes, and size/type indicators under explicit budgets.

## Resources and prompts

Canonical resources include server capabilities, sessions, per-database
metadata, jobs, investigations, debugger state, and redacted audit history
under `ida://sessions/{database}/...`. The supervisor rewrites session IDs to
worker-local database identities when routing reads. Existing `ida://idb/...`
resources remain compatibility aliases.

Prompts are provided for binary triage, function explanation, input-to-sink
tracing, component deobfuscation, binary comparison, patch review, and report
generation.

## Known capability gates

The active runtime reports unavailable debugger backends and unsupported
operations with `NOT_SUPPORTED`. Attach, pause, watchpoints, memory snapshots,
and bounded instruction/function/basic-block/step trace capture use native IDA
debugger APIs and therefore remain backend capability-gated. Microcode
generation requires a compatible Hex-Rays license. These gates remain visible
in the capability manifest and result metadata rather than silently degrading.
