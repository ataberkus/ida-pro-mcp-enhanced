"""Canonical vNext MCP tools, resources, and prompts.

The canonical layer intentionally delegates proven low-level IDA operations to
the legacy implementations.  This keeps one implementation of IDA behavior
while presenting a smaller and versioned public API.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import sys
from pathlib import Path
from threading import RLock
from typing import Annotated, Any, Literal, NoReturn, TypedDict, get_args
from urllib.parse import quote, unquote
from uuid import uuid4

from ida_pro_mcp.vnext.analysis import (
    node_matches,
    normalize_reference_flow_graph,
    normalized_match_token,
)
from ida_pro_mcp.vnext.contracts import (
    AnalysisEngine,
    AnalysisGraph,
    CapabilityManifest,
    ErrorCode,
    MutationOperation,
    SafetyScope,
    ToolEnvelope,
    VNextError,
)
from ida_pro_mcp.vnext.investigations import InvestigationManager
from ida_pro_mcp.vnext.jobs import CancelledError as JobCancelledError
from ida_pro_mcp.vnext.jobs import JobContext, JobManager
from ida_pro_mcp.vnext.transactions import RevisionTracker, TransactionManager

from .rpc import (
    MCP_AUDIT,
    MCP_SERVER,
    get_active_scopes,
    get_current_transport_session_id,
    get_workspace_policy,
    prompt,
    resolve_tool_paths,
    resource,
    tool,
)
try:
    from .sync import IDASyncError, idasync
    from .sync import CancelledError as SyncCancelledError
except ImportError:  # IDA-free contexts (tests) stub these modules
    IDASyncError = None  # type: ignore[assignment,misc]
    SyncCancelledError = None  # type: ignore[assignment,misc]

    def idasync(func):  # type: ignore[no-redef]
        # ponytail: no IDA main thread in unit tests; helpers run inline there.
        return func
try:
    from .zeromcp.jsonrpc import RequestCancelledError
except ImportError:
    RequestCancelledError = None  # type: ignore[assignment,misc]
try:
    from .zeromcp.mcp import McpToolError
except ImportError:
    McpToolError = None  # type: ignore[assignment,misc]


# Closed vocabularies. Signatures use Literal so MCP clients get `enum`
# constraints; bodies still `.lower()` for case-insensitive callers.
SearchKind = Literal["text", "regex", "bytes", "constant", "instruction"]
MemoryReadKind = Literal["bytes", "integer", "string", "global", "patch_diff"]
AnalysisMode = Literal["triage", "function", "component", "batch", "similar", "deep"]
GraphKind = Literal["xrefs", "xrefs_from", "xrefs_both", "calls", "cfg"]
DataflowDirection = Literal["forward", "backward", "both"]
SignatureFormat = Literal["ida", "x64dbg", "mask", "bitmask"]
InvestigationExportFormat = Literal["json", "markdown", "sarif"]
InvestigationSeverity = Literal["info", "low", "medium", "high", "critical"]
PythonExecuteMode = Literal["eval", "file"]
DebugSessionAction = Literal["start", "attach", "detach", "terminate", "status"]
DebugControlAction = Literal["continue", "step_into", "step_over", "pause", "run_to"]
DebugBreakpointAction = Literal["list", "add", "delete", "toggle", "watch"]
DebugMemoryAction = Literal["read", "write", "snapshot", "diff"]
DebugTraceAction = Literal["start", "status", "stop", "export"]


class AnalysisOptions(TypedDict, total=False):
    detail_level: Annotated[str, "triage verbosity: fast or full"]
    include_asm: Annotated[bool, "function mode: include disassembly"]
    max_depth: Annotated[int, "deep mode: reference-flow depth per target (1-20)"]
    direction: Annotated[str, "deep mode: dataflow direction forward, backward, or both"]
    limit: Annotated[int, "similar mode: maximum matches"]
    min_score: Annotated[float, "similar mode: minimum similarity score 0-1"]


class TaintOptions(TypedDict, total=False):
    include_traces: Annotated[bool, "include per-source traces in the result"]
    max_paths: Annotated[int, "maximum reported paths (1-1000)"]
    domains: Annotated[list[str], "propagation domains subset of register, stack, global, memory"]


class DebugTraceOptions(TypedDict, total=False):
    kind: Annotated[str, "trace kind: instruction, function, basic_block, or step"]
    clear: Annotated[bool, "clear the existing trace on start"]
    max_events: Annotated[int, "trace buffer size (1-1000000)"]
    offset: Annotated[int, "event listing offset"]
    limit: Annotated[int, "maximum events listed (1-5000)"]
    path: Annotated[str, "export destination path"]
    description: Annotated[str, "export trace description"]


class InvestigationBudgets(TypedDict, total=False):
    detail_level: Annotated[str, "triage verbosity: fast or full"]
    include_asm: Annotated[bool, "per-seed function analysis: include disassembly"]
    max_depth: Annotated[int, "per-seed dataflow depth (1-20)"]
    direction: Annotated[str, "per-seed dataflow direction forward, backward, or both"]


def _unsupported(what: str, value: Any, allowed: tuple[str, ...] | list[str]) -> NoReturn:
    raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported {what}: {value}. Allowed: {', '.join(allowed)}")


def _legacy_passthrough_errors() -> tuple:
    return tuple(
        cls
        for cls in (
            IDASyncError,
            SyncCancelledError,
            RequestCancelledError,
            JobCancelledError,
            McpToolError,
        )
        if isinstance(cls, type)
    )

_STATE_LOCK = RLock()
_JOBS: JobManager | None = None
_INVESTIGATIONS: InvestigationManager | None = None
_REVISIONS = RevisionTracker()
_TRANSACTIONS = TransactionManager(_REVISIONS)
_REVISION_HOOK: Any = None
_DEBUG_HOOK: Any = None
_DEBUG_SNAPSHOTS: dict[str, dict[str, Any]] = {}


def _load_idb_state(key: str) -> dict[str, Any]:
    from .http import config_json_get

    return config_json_get(f"vnext.{key}", {})


def _save_idb_state(key: str, state: dict[str, Any]) -> None:
    from .http import config_json_set

    config_json_set(f"vnext.{key}", state)


def _resource_database(database: str | None) -> str:
    return quote(database or "active", safe="")


def _job_changed(record: Any) -> None:
    uri = f"ida://sessions/{_resource_database(record.database)}/jobs/{record.job_id}"
    MCP_SERVER.notify_resource_updated(uri)


def _investigation_changed(record: Any) -> None:
    uri = (
        f"ida://sessions/{_resource_database(record.database)}"
        f"/investigations/{record.investigation_id}"
    )
    MCP_SERVER.notify_resource_updated(uri)


def _jobs() -> JobManager:
    global _JOBS
    with _STATE_LOCK:
        if _JOBS is None:
            _JOBS = JobManager(
                max_workers=2,
                max_jobs=256,
                load_state=lambda: _load_idb_state("jobs"),
                save_state=lambda state: _save_idb_state("jobs", state),
                on_change=_job_changed,
            )
        return _JOBS


def _investigations() -> InvestigationManager:
    global _INVESTIGATIONS
    with _STATE_LOCK:
        if _INVESTIGATIONS is None:
            _INVESTIGATIONS = InvestigationManager(
                load_state=lambda: _load_idb_state("investigations"),
                save_state=lambda state: _save_idb_state("investigations", state),
                on_change=_investigation_changed,
            )
        return _INVESTIGATIONS


def _legacy_call(name: str, arguments: dict[str, Any] | None = None, *, check_paths: bool = True) -> Any:
    # The active profile removes legacy tools from the externally visible
    # registry, while vNext workflows still use selected legacy implementations
    # internally.  Dispatch against the preserved implementation registry so
    # profile filtering does not break canonical analysis jobs.
    if check_paths:
        resolve_tool_paths(name, arguments or {})
    implementation = getattr(MCP_SERVER.tools, "_all_methods", {}).get(name)
    if implementation is None:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Legacy tool is not registered: {name}")
    try:
        return implementation(**(arguments or {}))
    except VNextError:
        raise
    except Exception as exc:
        if isinstance(exc, _legacy_passthrough_errors()):
            raise
        if isinstance(exc, (TypeError, ValueError, KeyError)):
            raise VNextError(ErrorCode.INVALID_OPERATION, f"Legacy tool failed: {name}: {exc}") from exc
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Legacy tool failed: {name}: {exc}") from exc


def _database_id_lookup() -> str:
    """Resolve the IDB identity. Must run on the IDA main thread."""
    try:
        import ida_loader

        path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if path:
            return str(Path(path).resolve())
    except Exception:
        pass
    try:
        import idaapi

        path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        if path:
            return str(Path(path).resolve())
    except Exception:
        pass
    return get_current_transport_session_id() or "active"


_database_id_sync = idasync(_database_id_lookup)


def _database_id() -> str:
    """Return the IDB identity.

    IDA 9.4 raises "Function can be called from the main thread only" for the
    path lookups above, so this dispatches to the IDA main thread when called
    from an MCP worker or job thread.
    """
    return _database_id_sync()


def _revision_changed(event: str) -> None:
    database = _database_id()
    _REVISIONS.bump(database)
    try:
        from .api_core import invalidate_strings_cache

        invalidate_strings_cache()
    except Exception:
        pass
    MCP_SERVER.notify_resource_updated(
        f"ida://sessions/{_resource_database(database)}/metadata"
    )


def _install_revision_hook() -> None:
    """Invalidate previews and caches for GUI, automation, and MCP IDB edits."""

    global _REVISION_HOOK
    if _REVISION_HOOK is not None:
        return
    try:
        import ida_idp
    except Exception:
        return

    class _RevisionHook(ida_idp.IDB_Hooks):
        def _changed(self, event: str) -> int:
            _revision_changed(event)
            return 0

        def renamed(self, *args: Any) -> int:
            return self._changed("renamed")

        def cmt_changed(self, *args: Any) -> int:
            return self._changed("comment")

        def extra_cmt_changed(self, *args: Any) -> int:
            return self._changed("extra_comment")

        def bookmark_changed(self, *args: Any) -> int:
            return self._changed("bookmark")

        def byte_patched(self, *args: Any) -> int:
            return self._changed("byte_patch")

        def make_code(self, *args: Any) -> int:
            return self._changed("make_code")

        def make_data(self, *args: Any) -> int:
            return self._changed("make_data")

        def destroyed_items(self, *args: Any) -> int:
            return self._changed("undefine")

        def func_added(self, *args: Any) -> int:
            return self._changed("function_added")

        def func_deleted(self, *args: Any) -> int:
            return self._changed("function_deleted")

        def func_updated(self, *args: Any) -> int:
            return self._changed("function_updated")

        def ti_changed(self, *args: Any) -> int:
            return self._changed("type")

        def op_ti_changed(self, *args: Any) -> int:
            return self._changed("operand_type")

        def op_type_changed(self, *args: Any) -> int:
            return self._changed("operand_display")

        def frame_udm_changed(self, *args: Any) -> int:
            return self._changed("stack_member")

        def frame_udm_created(self, *args: Any) -> int:
            return self._changed("stack_member")

        def frame_udm_deleted(self, *args: Any) -> int:
            return self._changed("stack_member")

        def local_types_changed(self, *args: Any) -> int:
            return self._changed("local_type")

        def segm_added(self, *args: Any) -> int:
            return self._changed("segment")

        def segm_deleted(self, *args: Any) -> int:
            return self._changed("segment")

        def segm_moved(self, *args: Any) -> int:
            return self._changed("segment")

        def closebase(self, *args: Any) -> int:
            global _JOBS, _INVESTIGATIONS
            with _STATE_LOCK:
                _JOBS = None
                _INVESTIGATIONS = None
            return 0

    hook = _RevisionHook()
    if hook.hook():
        _REVISION_HOOK = hook


def _install_debug_hook() -> None:
    """Publish debugger resource changes from native IDA callbacks."""

    global _DEBUG_HOOK
    if _DEBUG_HOOK is not None:
        return
    try:
        import ida_dbg
    except Exception:
        return

    class _DebuggerEventHook(ida_dbg.DBG_Hooks):
        def _updated(self) -> None:
            MCP_SERVER.notify_resource_updated(
                f"ida://sessions/{_resource_database(_database_id())}/debugger"
            )

        def dbg_process_start(self, *args: Any) -> None:
            self._updated()

        def dbg_process_attach(self, *args: Any) -> None:
            self._updated()

        def dbg_process_exit(self, *args: Any) -> None:
            self._updated()

        def dbg_process_detach(self, *args: Any) -> None:
            self._updated()

        def dbg_suspend_process(self, *args: Any) -> None:
            self._updated()

        def dbg_bpt_changed(self, *args: Any) -> None:
            self._updated()

        def dbg_thread_start(self, *args: Any) -> None:
            self._updated()

        def dbg_thread_exit(self, *args: Any) -> None:
            self._updated()

        def dbg_library_load(self, *args: Any) -> None:
            self._updated()

        def dbg_library_unload(self, *args: Any) -> None:
            self._updated()

        def dbg_trace(self, *args: Any) -> int:
            self._updated()
            return 0

    hook = _DebuggerEventHook()
    if hook.hook():
        _DEBUG_HOOK = hook


def _ida_capabilities() -> CapabilityManifest:
    """Return runtime capabilities, resolving IDA state on the main thread."""
    return _ida_capabilities_sync()


def _ida_capabilities_impl() -> CapabilityManifest:
    ida_version = None
    runtime = "gui"
    hexrays = False
    debugger = False
    try:
        import idaapi

        ida_version = str(idaapi.get_kernel_version())
    except Exception:
        pass
    if "idapro" in sys.modules:
        runtime = "idalib"
    try:
        import ida_hexrays  # noqa: F401

        hexrays = True
    except Exception:
        pass
    try:
        import ida_dbg  # noqa: F401

        debugger = True
    except Exception:
        pass
    engines = [AnalysisEngine.REFERENCE_FLOW.value]
    if hexrays:
        engines.append(AnalysisEngine.HEXRAYS_MICROCODE.value)
    return CapabilityManifest(
        runtime=runtime,
        ida_version=ida_version,
        python_version=platform.python_version(),
        database=_database_id(),
        safety_scopes=tuple(sorted(scope.value for scope in get_active_scopes())),
        analysis_engines=tuple(engines),
        hexrays_available=hexrays,
        debugger_available=debugger,
        resource_subscriptions=MCP_SERVER.resource_subscriptions_supported,
        database_revision=_REVISIONS.current(_database_id()),
    )


_ida_capabilities_sync = idasync(_ida_capabilities_impl)


def _encode_cursor_value(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor_value(cursor: str) -> dict[str, Any]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        if not isinstance(value, dict):
            raise TypeError("cursor payload must be an object")
        return value
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VNextError(ErrorCode.INVALID_OPERATION, "Invalid pagination cursor") from exc


def _encode_cursor(offset: int) -> str:
    return _encode_cursor_value({"offset": max(0, offset)})


def _decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        return max(0, int(_decode_cursor_value(cursor)["offset"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise VNextError(ErrorCode.INVALID_OPERATION, "Invalid pagination cursor") from exc


def _search_next_cursor(result: Any) -> str | None:
    """Convert a legacy offset cursor into the canonical opaque cursor."""
    if isinstance(result, list):
        for item in result:
            cursor = _search_next_cursor(item)
            if cursor is not None:
                return cursor
        return None
    if not isinstance(result, dict):
        return None
    value = result.get("next_offset")
    legacy_cursor = result.get("cursor")
    if value is None and isinstance(legacy_cursor, dict):
        value = legacy_cursor.get("next")
    if value is None:
        return None
    try:
        offset = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return _encode_cursor(offset)


def _result_truncated(result: Any) -> bool:
    if isinstance(result, list):
        return any(_result_truncated(item) for item in result)
    if not isinstance(result, dict):
        return False
    if result.get("truncated") is True or result.get("next_offset") is not None:
        return True
    cursor = result.get("cursor")
    if isinstance(cursor, dict) and cursor.get("next") is not None:
        return True
    return any(
        _result_truncated(value)
        for key, value in result.items()
        if key not in {"cursor", "next_offset"}
    )


def _per_target_cursor_states(
    cursor: str | None,
    target_count: int,
    key: str,
) -> list[dict[str, Any] | None]:
    """Decode one ``{offset[, start]}`` state per target (None = target exhausted)."""
    if not cursor:
        return [{"offset": 0} for _ in range(target_count)]
    value = _decode_cursor_value(cursor)
    if key not in value:
        return [{"offset": _decode_cursor(cursor)} for _ in range(target_count)]
    states = value[key]
    if not isinstance(states, list) or len(states) != target_count:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"{key.title()} cursor does not match targets")
    normalized: list[dict[str, Any] | None] = []
    for state in states:
        if state is None:
            normalized.append(None)
            continue
        try:
            entry: dict[str, Any] = {"offset": max(0, int(state["offset"]))}
        except (KeyError, TypeError, ValueError) as exc:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"Invalid {key} cursor state") from exc
        if state.get("start"):
            entry["start"] = str(state["start"])
        normalized.append(entry)
    return normalized


def _per_target_next_cursor(
    result: Any,
    pending: list[tuple[int, str, dict[str, Any]]],
    target_count: int,
    key: str,
) -> str | None:
    """Encode per-target continuation; collapses to a plain offset cursor when uniform."""
    if not isinstance(result, list):
        return None
    states: list[dict[str, Any] | None] = [None] * target_count
    for (target_index, _target, prior), item in zip(pending, result):
        if not isinstance(item, dict):
            continue
        if item.get("truncated") and item.get("next_start"):
            states[target_index] = {"offset": 0, "start": str(item["next_start"])}
            continue
        encoded = _search_next_cursor(item)
        if encoded is not None:
            state: dict[str, Any] = {"offset": _decode_cursor(encoded)}
            if prior.get("start"):
                state["start"] = prior["start"]
            states[target_index] = state
    active = [state for state in states if state is not None]
    if not active:
        return None
    if (
        len(active) == target_count
        and all(not state.get("start") for state in active)
        and len({state["offset"] for state in active}) == 1
    ):
        return _encode_cursor(active[0]["offset"])
    return _encode_cursor_value({key: states})


@tool
def server_capabilities() -> dict[str, Any]:
    """WHEN choosing which tool fits, read this first; it gates debug/python/file tools.
    RETURNS {runtime, ida, safety, engine, schema} capability manifest.
    LIMITS snapshot of current backend (debugger/hexrays flags flip with the IDB). NEXT analysis_run/mutation_preview within the allowed scopes."""

    return _ida_capabilities().to_dict()


@tool
def search(
    kind: Annotated[SearchKind, "text, regex, bytes, constant, or instruction"],
    targets: Annotated[list[str], "Search values or patterns"],
    limit: Annotated[int, "Maximum results"] = 100,
    cursor: Annotated[str | None, "Opaque continuation cursor"] = None,
) -> dict[str, Any]:
    """WHEN exact-value lookup is enough, use memory_read/entity_query instead.
    RETURNS {data, truncated, next_cursor} envelope; per-kind arity/pagination below.
    LIMITS text/regex take exactly 1 target (offset cursor); bytes/constant take N targets (offset cursor); instruction takes N mnemonics (per-target {offset,start} cursor, legacy insn_query, max_scan_insns 200000). NEXT follow up with memory_read/disassemble/graph_query."""
    normalized = str(kind).lower()
    legacy_tool = normalized
    if normalized == "instruction":
        states = _per_target_cursor_states(cursor, len(targets), "instruction")
        pending = [
            (index, target, state)
            for index, (target, state) in enumerate(zip(targets, states))
            if state is not None
        ]
        queries = []
        for _index, target, state in pending:
            query = {
                "mnem": target,
                "offset": state["offset"],
                "count": limit,
                "max_scan_insns": 200000,
                "allow_broad": True,
                "include_disasm": True,
            }
            if state.get("start"):
                query["start"] = state["start"]
            queries.append(query)
        result = _legacy_call("insn_query", {"queries": queries}) if queries else []
        next_cursor = _per_target_next_cursor(result, pending, len(targets), "instruction")
        legacy_tool = "insn_query"
    else:
        offset = _decode_cursor(cursor)
        if normalized == "text":
            if len(targets) != 1:
                raise VNextError(ErrorCode.INVALID_OPERATION, "Text search accepts one pattern")
            result = _legacy_call(
                "search_text",
                {
                    "pattern": targets[0],
                    "limit": limit,
                    "start": hex(offset) if cursor else "",
                    "end": "",
                    "regex": False,
                    "case_sensitive": False,
                    "include": "all",
                    "code_only": False,
                },
            )
            legacy_tool = "search_text"
        elif normalized == "regex":
            if len(targets) != 1:
                raise VNextError(ErrorCode.INVALID_OPERATION, "Regex search accepts one pattern")
            result = _legacy_call(
                "entity_query",
                {"queries": {"kind": "strings", "regex": targets[0], "case_sensitive": False, "offset": offset, "count": limit}},
            )
            legacy_tool = "entity_query"
        elif normalized == "bytes":
            result = _legacy_call("find_bytes", {"patterns": targets, "limit": limit, "offset": offset})
            legacy_tool = "find_bytes"
        elif normalized == "constant":
            result = _legacy_call(
                "find",
                {
                    "type": "immediate",
                    "targets": targets,
                    "limit": limit,
                    "offset": offset,
                },
            )
            legacy_tool = "find"
        else:
            _unsupported("search kind", kind, get_args(SearchKind))
        next_cursor = _search_next_cursor(result)
    return ToolEnvelope(
        result,
        provenance={"legacy_tool": legacy_tool},
        truncated=next_cursor is not None or _result_truncated(result),
        next_cursor=next_cursor,
    ).to_dict()


_DEFAULT_BYTES_READ_SIZE = 16


def _normalize_memory_queries(kind: str, queries: list[dict[str, Any]] | list[str]) -> list[Any]:
    """Normalize memory_read queries to the shapes expected by legacy tools."""
    if kind == "bytes":
        normalized: list[Any] = []
        for item in queries:
            if isinstance(item, str):
                normalized.append({"addr": item, "size": _DEFAULT_BYTES_READ_SIZE})
            elif isinstance(item, dict):
                normalized.append(item)
            else:
                raise VNextError(
                    ErrorCode.INVALID_OPERATION,
                    "bytes queries must be address strings or {addr, size} objects",
                )
        return normalized

    if kind == "integer":
        for item in queries:
            if isinstance(item, str):
                raise VNextError(
                    ErrorCode.INVALID_OPERATION,
                    "integer queries require objects of shape {addr, ty}",
                )
        return list(queries)

    # string / global accept bare address/name strings.
    return list(queries)


@tool
def memory_read(
    kind: Annotated[MemoryReadKind, "bytes, integer, string, global, or patch_diff"],
    queries: Annotated[
        list[dict[str, Any]] | list[str] | None,
        "Address queries. bytes: '0x...' (size defaults to 16) or {addr,size}; "
        "integer: {addr,ty} where ty is u8/u32/uint32/i16le/u64be/etc; string/global: address or name strings; "
        "patch_diff: ignored (Phase C hook owns the IDA patched-bytes diff)",
    ] = None,
) -> dict[str, Any]:
    """WHEN reading one static fact, use this; for live process memory use debug_memory.
    RETURNS {data, truncated, next_cursor} envelope with per-kind rows below.
    LIMITS bytes/integer/string/global delegate to one legacy read each (no pagination); patch_diff is reserved for the Phase C patched-bytes diff (queries ignored). NEXT disassemble/graph_query for code context."""

    mapping = {
        "bytes": ("get_bytes", "regions"),
        "integer": ("get_int", "queries"),
        "string": ("get_string", "addrs"),
        "global": ("get_global_value", "queries"),
    }
    normalized_kind = str(kind).lower()
    if normalized_kind == "patch_diff":
        from . import api_recovery

        return ToolEnvelope({"text": api_recovery.patch_diff_text()}, provenance={"legacy_tool": "visit_patched_bytes"}).to_dict()
    if normalized_kind not in mapping:
        _unsupported("memory read kind", kind, get_args(MemoryReadKind))
    name, argument_name = mapping[normalized_kind]
    normalized = _normalize_memory_queries(normalized_kind, list(queries or []))
    return ToolEnvelope(
        _legacy_call(name, {argument_name: normalized}),
        provenance={"legacy_tool": name},
    ).to_dict()


@tool
def disassemble(
    addr: Annotated[str, "Function name or hexadecimal address"],
    max_instructions: Annotated[int, "Maximum instructions"] = 500,
    offset: Annotated[int, "Instruction offset"] = 0,
    include_total: Annotated[bool, "Include total instruction count"] = False,
) -> dict[str, Any]:
    """WHEN one function body is enough, use this instead of analysis_run(function).
    RETURNS {data, truncated} envelope with canonical hex addresses.
    LIMITS offset/max_instructions paginate one function; large functions hit the rpc 50k download indirection. NEXT graph_query(cfg) for blocks."""
    result = _legacy_call("disasm", {"addr": addr, "max_instructions": max_instructions, "offset": offset, "include_total": include_total})
    return ToolEnvelope(result, provenance={"legacy_tool": "disasm"}).to_dict()


@tool
def signature_create(
    addrs: Annotated[list[str], "Functions or addresses to sign"],
    format: Annotated[SignatureFormat, "ida, x64dbg, mask, or bitmask"] = "ida",
    wildcard_operands: Annotated[bool, "Wildcard relocatable operands"] = True,
    max_length: Annotated[int, "Maximum signature length"] = 250,
) -> dict[str, Any]:
    """WHEN matching this function elsewhere, use this; for callers/callees use graph_query.
    RETURNS {data, truncated} envelope with one signature row per address.
    LIMITS max_length caps signature bytes; wildcard_operands wildcards relocatable operands. NEXT search(bytes) to find matches."""
    normalized_format = str(format).lower()
    if normalized_format not in get_args(SignatureFormat):
        _unsupported("signature format", format, get_args(SignatureFormat))
    result = _legacy_call("make_signature_for_function", {"addrs": addrs, "format": normalized_format, "wildcard_operands": wildcard_operands, "max_length": max_length})
    return ToolEnvelope(result, provenance={"legacy_tool": "make_signature_for_function"}).to_dict()


def _analysis_sync(mode: str, targets: list[str], options: dict[str, Any]) -> Any:
    if mode == "triage":
        return _legacy_call("survey_binary", {"detail_level": options.get("detail_level", "fast")})
    if mode == "function":
        if len(targets) != 1:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Function analysis requires one target")
        return _legacy_call("analyze_function", {"addr": targets[0], "include_asm": bool(options.get("include_asm", False))})
    if mode == "component":
        return _legacy_call("analyze_component", {"addrs": targets})
    if mode == "batch":
        return _legacy_call("analyze_batch", {"queries": [{"addr": target} for target in targets]})
    if mode == "similar":
        from . import api_recovery
        from .utils import resolve_address_or_name

        if len(targets) != 1:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Similar analysis requires one target")
        return api_recovery.similar_functions(
            resolve_address_or_name(targets[0]),
            int(options.get("limit", 20) or 20),
            float(options.get("min_score", 0.3) or 0.3),
        )
    _unsupported("analysis mode", mode, get_args(AnalysisMode))


@tool
def analysis_run(
    mode: Annotated[AnalysisMode, "triage, function, component, batch, similar, or deep"],
    targets: Annotated[list[str] | None, "Seed functions or addresses"] = None,
    options: Annotated[AnalysisOptions | None, "Analysis budgets and mode options"] = None,
) -> dict[str, Any]:
    """WHEN choosing analysis depth, use this; for one disassembly use disassemble.
    RETURNS inline {data,...} envelope, or a job record for deep. Per-mode arity below.
    LIMITS triage takes no targets (detail_level fast/full); function/similar take 1 target (similar ranks mnemonic 3-gram matches, options limit/min_score); component/batch take N targets; deep submits a cancellable job (options max_depth 1-20, direction forward/backward/both) and large outputs use the rpc 50k download indirection. NEXT dataflow_trace/taint_analyze on the targets."""
    normalized = str(mode).lower()
    effective_options = dict(options or {})
    if normalized not in get_args(AnalysisMode):
        _unsupported("analysis mode", mode, get_args(AnalysisMode))
    effective_targets = list(targets or [])
    if normalized != "deep":
        return ToolEnvelope(_analysis_sync(normalized, effective_targets, effective_options), provenance={"mode": normalized}).to_dict()

    def run(context: JobContext) -> dict[str, Any]:
        context.progress(0.05, "triage")
        triage = _analysis_sync("triage", [], effective_options)
        total = max(1, len(effective_targets))
        depth = max(1, min(int(effective_options.get("max_depth", 3) or 3), 20))
        direction = str(effective_options.get("direction", "both") or "both")
        for index, target in enumerate(effective_targets):
            context.check_cancelled()
            analysis = _analysis_sync("function", [target], effective_options)
            try:
                flow = dataflow_trace(target, direction, depth)
            except Exception as exc:
                flow = {"error": str(exc), "target": target}
            functions.append({"target": target, "analysis": analysis, "dataflow": flow})
            context.progress(0.1 + 0.8 * ((index + 1) / total), f"analyzed {target}")
        context.progress(0.95, "assembling result")
        return ToolEnvelope(
            {"triage": triage, "functions": functions},
            provenance={"mode": "deep", "database": _database_id()},
        ).to_dict()

    return _jobs().submit("analysis.deep", run, database=_database_id()).to_dict(include_result=False)


@tool
def graph_query(
    kind: Annotated[GraphKind, "xrefs, xrefs_from, xrefs_both, calls, or cfg"],
    targets: Annotated[list[str], "Root functions or addresses"],
    max_depth: Annotated[int, "Maximum traversal depth"] = 3,
    limit: Annotated[int, "Maximum nodes or blocks"] = 1000,
    cursor: Annotated[str | None, "Opaque continuation cursor"] = None,
) -> dict[str, Any]:
    """WHEN code references matter, use this instead of raw xrefs/disassembly.
    RETURNS {data, truncated, next_cursor} envelope; per-kind arity/pagination below.
    LIMITS xrefs/xrefs_from/xrefs_both take N targets (per-target offset cursor, legacy xref_query); cfg takes N targets (per-target offset cursor, legacy basic_blocks, max_blocks=limit); calls takes N roots (no cursor, max_nodes=limit, max_edges=2*limit). NEXT dataflow_trace for value flow."""
    normalized = str(kind).lower()

    if normalized in {"xrefs", "xrefs_from", "xrefs_both", "cfg"}:
        states = _per_target_cursor_states(cursor, len(targets), "graph")
        pending = [
            (index, target, state)
            for index, (target, state) in enumerate(zip(targets, states))
            if state is not None
        ]
        if normalized == "cfg":
            result = []
            for _index, target, state in pending:
                page = _legacy_call(
                    "basic_blocks",
                    {
                        "addrs": [target],
                        "max_blocks": limit,
                        "offset": state["offset"],
                    },
                )
                result.extend(page if isinstance(page, list) else [page])
        else:
            direction = {
                "xrefs": "to",
                "xrefs_from": "from",
                "xrefs_both": "both",
            }[normalized]
            result = _legacy_call(
                "xref_query",
                {
                    "queries": [
                        {
                            "query": target,
                            "direction": direction,
                            "offset": state["offset"],
                            "count": limit,
                        }
                        for _index, target, state in pending
                    ]
                },
            )
        next_cursor = _per_target_next_cursor(result, pending, len(targets), "graph")
    elif normalized == "calls":
        if cursor:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Call graphs do not support cursor continuation")
        result = _legacy_call("callgraph", {"roots": targets, "max_depth": max_depth, "max_nodes": limit, "max_edges": limit * 2, "max_edges_per_func": 100})
        next_cursor = None
    else:
        _unsupported("graph kind", kind, get_args(GraphKind))
    return ToolEnvelope(
        result,
        provenance={"kind": normalized},
        truncated=next_cursor is not None or _result_truncated(result),
        next_cursor=next_cursor,
    ).to_dict()


@tool
def dataflow_trace(
    addr: Annotated[str, "Seed address, string, or function"],
    direction: Annotated[DataflowDirection, "forward, backward, or both"] = "forward",
    max_depth: Annotated[int, "Maximum reference depth"] = 3,
) -> dict[str, Any]:
    """WHEN asking where a value flows, use this; for sink matching use taint_analyze.
    RETURNS {engine, fidelity, nodes, edges, warnings, truncated} graph dict.
    LIMITS semantic microcode engine when Hex-Rays is present, else reference-flow fallback (unsupported_edges labeled); max_depth caps reference hops. NEXT taint_analyze for source/sink correlation."""
    normalized = str(direction).lower()

    try:
        from .hexrays_dataflow import trace_microcode

        return trace_microcode(addr, direction=normalized, max_depth=max_depth)
    except VNextError as exc:
        if exc.code is not ErrorCode.NOT_SUPPORTED:
            raise
        fallback_warning = f"Hex-Rays microcode unavailable: {exc}"

    if normalized not in get_args(DataflowDirection):
        _unsupported("data-flow direction", direction, get_args(DataflowDirection))
    result = _legacy_call("trace_data_flow", {"addr": addr, "direction": normalized, "max_depth": max_depth})
    nodes, edges, truncated = normalize_reference_flow_graph(result if isinstance(result, dict) else {})
    warnings = [fallback_warning, "Result is reference flow, not semantic data flow"]
    if isinstance(result, dict) and result.get("error"):
        warnings.append(str(result["error"]))
    graph = AnalysisGraph(
        engine=AnalysisEngine.REFERENCE_FLOW,
        fidelity="reference",
        nodes=nodes,
        edges=edges,
        unsupported_edges=[
            {"kind": "semantic_def_use", "reason": "Hex-Rays microcode is unavailable"},
            {"kind": "memory_alias", "reason": "reference flow does not model aliases"},
        ],
        warnings=warnings,
        truncated=truncated,
    )
    return graph.to_dict()


@tool
def taint_analyze(
    sources: Annotated[list[str], "Source addresses or symbols"],
    sinks: Annotated[list[str], "Sink addresses or symbols"],
    sanitizers: Annotated[list[str] | None, "Known sanitizer symbols"] = None,
    options: Annotated[TaintOptions | None, "Propagation domains and result budgets"] = None,
) -> dict[str, Any]:
    """WHEN matching sources to sinks, use this instead of raw dataflow_trace walks.
    RETURNS {engine, fidelity, hits, sanitizer_annotations, warnings, truncated} dict.
    LIMITS BFS over reference/microcode graphs capped by max_depth and options.max_paths (1-1000); domains filter register/stack/global/memory; large outputs use the rpc 50k download indirection. NEXT investigation_add_finding to record hits."""
    effective_sanitizers = list(sanitizers or [])
    traces = [dataflow_trace(source, "forward", max_depth) for source in sources]
    include_traces = bool(effective_options.get("include_traces", False))
    max_paths = max(1, min(int(effective_options.get("max_paths", 100)), 1000))
    enabled_domains = set(effective_options.get("domains", ["register", "stack", "global", "memory"]))
    sink_set = {normalized_match_token(sink) for sink in sinks}
    sanitizer_set = {normalized_match_token(item) for item in effective_sanitizers}
    hits: list[dict[str, Any]] = []
    sanitizer_annotations: list[dict[str, Any]] = []
    warnings: list[str] = []
    for source, trace in zip(sources, traces):
        nodes = {str(node["id"]): node for node in trace.get("nodes", []) if node.get("id") is not None}
        adjacency: dict[str, list[str]] = {}
        for edge in trace.get("edges", []):
            src = edge.get("source") or edge.get("from")
            dst = edge.get("target") or edge.get("to")
            if src is None or dst is None:
                continue
            adjacency.setdefault(str(src), []).append(str(dst))
        source_token = normalized_match_token(source)
        starts = [node_id for node_id, node in nodes.items() if node_matches(node, {source_token})]
        if not starts:
            warnings.append(f"Source {source!r} was not found in the trace graph")
            continue
        queue = [(node_id, [node_id]) for node_id in starts]
        visited = set(starts)
        while queue and len(hits) < max_paths:
            node_id, path = queue.pop(0)
            node = nodes[node_id]
            matched_sanitizers = sorted(token for token in sanitizer_set if node_matches(node, {token}))
            if matched_sanitizers:
                sanitizer_annotations.append(
                    {"source": source, "node": node_id, "sanitizers": matched_sanitizers, "action": "propagation_stopped"}
                )
                continue
            matched_sinks = sorted(token for token in sink_set if node_matches(node, {token}))
            if matched_sinks:
                domains = sorted(_node_domains([nodes[item] for item in path]) & enabled_domains)
                fidelity = str(trace.get("fidelity", "reference"))
                hits.append(
                    {
                        "source": source,
                        "sinks": matched_sinks,
                        "path": path,
                        "addresses": [nodes[item].get("address") or nodes[item].get("addr") for item in path if nodes[item].get("address") or nodes[item].get("addr")],
                        "domains": domains,
                        "confidence": 0.9 if fidelity.startswith("semantic") else 0.4,
                        "engine": trace.get("engine", AnalysisEngine.REFERENCE_FLOW.value),
                    }
                )
            if len(path) > max_depth:
                continue
            for neighbor in adjacency.get(node_id, []):
                if neighbor in nodes and neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, [*path, neighbor]))
    engines = sorted({str(trace.get("engine", AnalysisEngine.REFERENCE_FLOW.value)) for trace in traces})
    semantic = engines == [AnalysisEngine.HEXRAYS_MICROCODE.value]
    if not semantic:
        warnings.append("At least one trace used reference-flow fallback")
    if not include_traces:
        warnings.append("Per-source traces omitted (pass options.include_traces=true to include them).")
    return {
        "engine": engines[0] if len(engines) == 1 else "mixed",
        "fidelity": "semantic_intraprocedural" if semantic else "reference_or_mixed",
        "sources": sources,
        "sinks": sinks,
        "sanitizers": effective_sanitizers,
        "domains": sorted(enabled_domains),
        "hits": hits,
        "sanitizer_annotations": sanitizer_annotations,
        "traces": traces if include_traces else [],
        "truncated": len(hits) >= max_paths,
        "unsupported_edges": [
            {"kind": "interprocedural_alias", "reason": "callee summaries are not yet available for every call"},
            {"kind": "thread_handoff", "reason": "concurrent taint propagation is not modeled"},
        ],
        "warnings": warnings,
    }


def _node_domains(nodes: list[dict[str, Any]]) -> set[str]:
    import re

    domains: set[str] = set()
    rendered = " ".join(
        f"{node.get('definitions', '')} {node.get('uses', '')}".lower()
        for node in nodes
    )
    if re.search(r"\b(sp|stk|stack|stackvar)\b|@sp", rendered):
        domains.add("stack")
    text = rendered
    if "[" in text or re.search(r"\bmem\b", text):
        domains.add("memory")
    if re.search(r"\b(global|got|plt)\b|\.data\b|\.bss\b", text):
        domains.add("global")
    if rendered.strip() and not domains:
        domains.add("register")
    return domains


@tool
def job_status(job_id: Annotated[str, "Job identifier"]) -> dict[str, Any]:
    """WHEN polling a deep analysis/investigation job, use this; for data use job_result.
    RETURNS job record without the result payload.
    LIMITS terminal states are persisted; interrupted jobs restore as interrupted. NEXT job_result when done."""
    return _jobs().status(job_id, include_result=False)


@tool
def job_cancel(job_id: Annotated[str, "Job identifier"]) -> dict[str, Any]:
    """WHEN a deep job is no longer needed, use this instead of waiting.
    RETURNS {job_id, cancel_requested}.
    LIMITS cooperative: running jobs observe cancellation at the next checkpoint. NEXT job_status to confirm."""
    return {"job_id": job_id, "cancel_requested": _jobs().cancel(job_id)}


@tool
def job_result(
    job_id: Annotated[str, "Completed job identifier"],
    cursor: Annotated[str | None, "Opaque result cursor"] = None,
    limit: Annotated[int, "Maximum list items"] = 100,
) -> dict[str, Any]:
    """WHEN a deep job finished, use this; for progress use job_status.
    RETURNS {data, truncated, next_cursor} envelope; lists paginate by cursor/limit.
    LIMITS non-list results return whole; list pages cap at 1000 items and large outputs use the rpc 50k download indirection. NEXT investigation_add_finding to record conclusions."""
    result = _jobs().result(job_id)
    if not isinstance(result, list):
        return ToolEnvelope(result).to_dict()
    offset = _decode_cursor(cursor)
    page = result[offset : offset + max(1, min(limit, 1000))]
    next_offset = offset + len(page)
    next_cursor = _encode_cursor(next_offset) if next_offset < len(result) else None
    return ToolEnvelope(page, truncated=next_cursor is not None, next_cursor=next_cursor).to_dict()


@tool
def investigation_start(
    objective: Annotated[str, "Investigation goal"],
    seeds: Annotated[list[str] | None, "Seed functions, addresses, or strings"] = None,
    budgets: Annotated[InvestigationBudgets | None, "Depth and result budgets"] = None,
) -> dict[str, Any]:
    """WHEN a multi-step question needs resumable evidence, use this instead of one-shot analysis_run.
    RETURNS the investigation record with its background job id.
    LIMITS seeds fan out to one function analysis each; budgets carry detail_level/include_asm/max_depth/direction; findings arrive via investigation_add_finding. NEXT investigation_get/job_status to follow progress."""
    effective_seeds = list(seeds or [])
    effective_budgets = dict(budgets or {})
    manager = _investigations()
    record = manager.create(objective, database=_database_id(), seeds=effective_seeds)
    def run(context: JobContext) -> dict[str, Any]:
        try:
            context.progress(0.05, "triage")
            triage = _analysis_sync("triage", [], effective_budgets)
            analyses = []
            for index, seed in enumerate(effective_seeds):
                context.check_cancelled()
                analyses.append(_analysis_sync("function", [seed], effective_budgets))
                context.progress(0.1 + 0.8 * ((index + 1) / max(1, len(effective_seeds))), f"analyzed {seed}")
            manager.set_state(record.investigation_id, "completed", triage=triage, analyses=analyses)
            return manager.get(record.investigation_id).to_dict()
        except JobCancelledError:
            manager.set_state(record.investigation_id, "cancelled")
            raise
        except Exception:
            manager.set_state(record.investigation_id, "failed")
            raise

    job = _jobs().submit("investigation.deep", run, database=record.database)
    manager.set_job(record.investigation_id, job.job_id)
    return manager.get(record.investigation_id).to_dict()


@tool
def investigation_get(investigation_id: Annotated[str, "Investigation identifier"]) -> dict[str, Any]:
    """WHEN following a started investigation, use this; for jobs use job_status.
    RETURNS the persisted investigation record with findings and evidence.
    LIMITS read-only view; state changes only via add_finding or the background job. NEXT investigation_add_finding/investigation_export."""
    return _investigations().get(investigation_id).to_dict()


@tool
def investigation_add_finding(
    investigation_id: Annotated[str, "Investigation identifier"],
    title: Annotated[str, "Finding title"],
    description: Annotated[str, "Finding description"],
    severity: Annotated[InvestigationSeverity, "info, low, medium, high, or critical"] = "info",
    confidence: Annotated[float, "Confidence from 0 to 1"] = 0.5,
    evidence: Annotated[list[dict[str, Any]] | None, "Evidence records"] = None,
    tags: Annotated[list[str] | None, "Finding tags"] = None,
) -> dict[str, Any]:
    """WHEN a conclusion has tool evidence, use this; bare notes do not belong here.
    RETURNS the created finding record.
    LIMITS severity is info/low/medium/high/critical; confidence clamps to 0-1; evidence entries need addr or data. NEXT investigation_export for the report."""
    normalized_severity = str(severity).lower()
    if normalized_severity not in get_args(InvestigationSeverity):
        _unsupported("investigation severity", severity, get_args(InvestigationSeverity))
    manager = _investigations()
    finding = manager.add_finding(
        investigation_id,
        title=title,
        description=description,
        severity=normalized_severity,
        confidence=confidence,
        evidence=list(evidence or []),
        tags=list(tags or []),
    )
    return finding.to_dict()


@tool
def investigation_export(
    investigation_id: Annotated[str, "Investigation identifier"],
    format: Annotated[InvestigationExportFormat, "json, markdown, or sarif"] = "markdown",
    path: Annotated[str | None, "Optional output path"] = None,
) -> dict[str, Any]:
    """WHEN the record is complete, use this; generate_report prompts the same flow.
    RETURNS {format, content} inline or {path, format, bytes} when path is set.
    LIMITS json/markdown/sarif only; invalid formats raise NOT_SUPPORTED with Allowed list. NEXT write the file yourself if path was omitted."""
    normalized_format = str(format).lower()
    if normalized_format not in get_args(InvestigationExportFormat):
        _unsupported("investigation export format", format, get_args(InvestigationExportFormat))
    content = _investigations().export(investigation_id, normalized_format)
    if path:
        output = get_workspace_policy().resolve(path, must_exist=False)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        return {"path": str(output), "format": format, "bytes": len(content.encode("utf-8"))}
    return {"format": format, "content": content}


_OPERATION_TARGETS: dict[str, tuple[str, str, SafetyScope]] = {
    "rename": ("rename", "batch", SafetyScope.ANNOTATE),
    "comment": ("set_comments", "items", SafetyScope.ANNOTATE),
    "append_comment": ("append_comments", "items", SafetyScope.ANNOTATE),
    "bookmark": ("add_bookmark", "item", SafetyScope.ANNOTATE),
    "declare_type": ("declare_type", "decls", SafetyScope.ANNOTATE),
    "set_type": ("set_type", "edits", SafetyScope.ANNOTATE),
    "patch_bytes": ("patch", "patches", SafetyScope.MODIFY),
    "write_integer": ("put_int", "items", SafetyScope.MODIFY),
    "patch_asm": ("patch_asm", "items", SafetyScope.MODIFY),
    "define_function": ("define_func", "items", SafetyScope.MODIFY),
    "define_code": ("define_code", "items", SafetyScope.MODIFY),
    "undefine": ("undefine", "items", SafetyScope.MODIFY),
    "set_operand_type": ("set_op_type", "items", SafetyScope.MODIFY),
    "make_data": ("make_data", "items", SafetyScope.MODIFY),
    "declare_stack": ("declare_stack", "items", SafetyScope.ANNOTATE),
    "delete_stack": ("delete_stack", "items", SafetyScope.ANNOTATE),
    "apply_flirt": ("apply_flirt_signature", "items", SafetyScope.MODIFY),
    "load_til": ("load_type_library", "items", SafetyScope.MODIFY),
    "save_database": ("idb_save", "path", SafetyScope.FILESYSTEM),
}

_MUTATION_KIND_ALIASES = {
    "set_name": "rename",
    "rename_func": "rename",
    "rename_function": "rename",
    "rename_global": "rename",
    "rename_data": "rename",
}

_RENAME_BATCH_KEYS = frozenset({"func", "data", "global", "globals", "local", "stack"})
_RENAME_PASSTHROUGH_KEYS = ("allow_overwrite", "dry_run", "stop_on_error")
_MUTATION_META_KEYS = frozenset({"kind", "arguments", "scope"})

_SCOPE_RANK = {
    SafetyScope.READ: 0,
    SafetyScope.ANNOTATE: 1,
    SafetyScope.MODIFY: 2,
    SafetyScope.FILESYSTEM: 3,
    SafetyScope.DEBUG: 4,
    SafetyScope.PYTHON: 5,
}


def _as_dict_list(value: Any) -> list[dict[str, Any]] | None:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return None


def _parse_mutation_address(raw: Any, *, index: int, field: str = "addr") -> str:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raise VNextError(
            ErrorCode.INVALID_OPERATION,
            f"Mutation operation {index} has an empty address",
        )
    if isinstance(raw, int):
        return hex(raw)
    text = str(raw).strip()
    try:
        int(text, 0)
    except ValueError as exc:
        raise VNextError(
            ErrorCode.INVALID_OPERATION,
            f"Mutation operation {index} failed to parse {field}: {text}",
        ) from exc
    return text


def _copy_passthrough(source: dict[str, Any], dest: dict[str, Any], keys: tuple[str, ...]) -> None:
    for key in keys:
        if key in source:
            dest[key] = source[key]


def _normalize_comment_item(item: dict[str, Any], *, index: int) -> dict[str, Any]:
    addr = _parse_mutation_address(item.get("addr"), index=index)
    comment = item.get("comment")
    if comment is None:
        comment = item.get("text")
    if comment is None:
        raise VNextError(
            ErrorCode.INVALID_OPERATION,
            f"Mutation operation {index} comment is missing comment text",
        )
    normalized = {"addr": addr, "comment": str(comment)}
    _copy_passthrough(item, normalized, ("scope", "dedupe"))
    return normalized


def _reshape_mutation_arguments(kind: str, arguments: dict[str, Any], *, index: int = 0) -> tuple[str, dict[str, Any]]:
    """Normalize the kinds/flat forms documented on mutation_preview into canonical arguments."""
    canonical = _MUTATION_KIND_ALIASES.get(kind, kind)
    args = dict(arguments)

    if canonical == "rename":
        if any(key in args for key in _RENAME_BATCH_KEYS):
            for key in _RENAME_BATCH_KEYS:
                for item in _as_dict_list(args.get(key)) or []:
                    if "addr" in item:
                        item["addr"] = _parse_mutation_address(item["addr"], index=index)
            return canonical, args
        if "addr" in args or "name" in args:
            parsed_addr = _parse_mutation_address(args.get("addr"), index=index)
            if not args.get("name"):
                raise VNextError(
                    ErrorCode.INVALID_OPERATION,
                    f"Mutation operation {index} rename is missing name",
                )
            reshaped: dict[str, Any] = {"func": [{"addr": parsed_addr, "name": str(args["name"])}]}
            _copy_passthrough(args, reshaped, _RENAME_PASSTHROUGH_KEYS)
            return canonical, reshaped

    elif canonical in {"comment", "append_comment"}:
        items = _as_dict_list(args.get("items"))
        if items is not None:
            return canonical, {"items": [_normalize_comment_item(item, index=index) for item in items]}
        if any(key in args for key in ("addr", "comment", "text")):
            return canonical, {"items": [_normalize_comment_item(args, index=index)]}

    elif canonical == "set_type":
        edits = _as_dict_list(args.get("edits"))
        if edits is not None:
            for edit in edits:
                if "addr" in edit:
                    edit["addr"] = _parse_mutation_address(edit["addr"], index=index)
            return canonical, {**args, "edits": edits}
        if args.get("addr") and args.get("type"):
            edit = {"addr": _parse_mutation_address(args["addr"], index=index), "type": str(args["type"])}
            _copy_passthrough(args, edit, ("kind", "name", "variable"))
            return canonical, {"edits": [edit]}

    elif canonical == "declare_type" and not args.get("decls") and args.get("decl"):
        return canonical, {"decls": args["decl"]}

    return canonical, args


def _operation_payload_empty(kind: str, arguments: dict[str, Any]) -> bool:
    _tool_name, argument_name, _scope = _OPERATION_TARGETS[kind]
    if kind == "rename":
        for key in _RENAME_BATCH_KEYS:
            items = arguments.get(key)
            if isinstance(items, list) and items:
                return False
            if isinstance(items, dict) and items:
                return False
        return True
    if kind in {"comment", "append_comment"}:
        items = arguments.get("items")
        return not items
    if kind == "set_type":
        return not arguments.get("edits")
    if kind == "declare_type":
        decls = arguments.get("decls")
        return decls in (None, "", [])
    if argument_name == "path":
        return not str(arguments.get("path") or "").strip()
    if argument_name == "item":
        return not arguments
    payload = arguments.get(argument_name)
    if payload is None:
        return not arguments
    if isinstance(payload, list):
        return len(payload) == 0
    if isinstance(payload, dict):
        return len(payload) == 0
    if isinstance(payload, str):
        return not payload.strip()
    return False


def _merge_mutation_fields(value: dict[str, Any]) -> dict[str, Any]:
    raw_arguments = dict(value.get("arguments") or {})
    for key, val in value.items():
        if key not in _MUTATION_META_KEYS and key not in raw_arguments:
            raw_arguments[key] = val
    return raw_arguments


def _parse_operations(values: list[dict[str, Any]]) -> list[MutationOperation]:
    operations = []
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise VNextError(ErrorCode.INVALID_OPERATION, f"Mutation operation {index} must be an object")
        raw_kind = str(value.get("kind", ""))
        raw_arguments = value.get("arguments", {})
        if raw_arguments is None:
            raw_arguments = {}
        if not isinstance(raw_arguments, dict):
            raise VNextError(
                ErrorCode.INVALID_OPERATION,
                f"Mutation operation {index} arguments must be an object",
            )
        merged = _merge_mutation_fields(value)
        kind, arguments = _reshape_mutation_arguments(raw_kind, merged, index=index)
        target = _OPERATION_TARGETS.get(kind)
        if target is None:
            allowed = ", ".join(sorted(_OPERATION_TARGETS))
            raise VNextError(
                ErrorCode.INVALID_OPERATION,
                f"Unsupported mutation kind: {raw_kind}. Allowed: {allowed}",
            )
        if _operation_payload_empty(kind, arguments):
            raise VNextError(
                ErrorCode.INVALID_OPERATION,
                f"Mutation operation {index} {kind} is missing required fields",
            )
        scope = target[2]
        raw_scope = value.get("scope")
        if raw_scope is not None:
            try:
                client_scope = SafetyScope(str(raw_scope).lower())
            except ValueError:
                raise VNextError(
                    ErrorCode.INVALID_OPERATION,
                    f"Mutation operation {index} has an unknown scope: {raw_scope!r}",
                )
            if _SCOPE_RANK[client_scope] > _SCOPE_RANK[scope]:
                scope = client_scope
        operations.append(MutationOperation(kind, arguments, scope))
    return operations


def _legacy_result_failed(result: Any) -> str | None:
    errors: list[str] = []

    def collect(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if value.get("ok") is False:
                errors.append(f"{path}: {value.get('error') or 'operation failed'}")
                return
            if value.get("error") and value.get("ok") is not True:
                errors.append(f"{path}: {value['error']}")
                return
            for key, nested in value.items():
                if key not in {"summary", "error"}:
                    collect(nested, f"{path}.{key}")
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                collect(nested, f"{path}[{index}]")

    collect(result, "$")
    return "; ".join(errors) if errors else None


def _checkpoint_path(transaction_id: str) -> str:
    cache_root = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    directory = cache_root / "ida-pro-mcp" / "checkpoints"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{transaction_id}.i64"
    result = _legacy_call("idb_save", {"path": str(path)}, check_paths=False)
    failure = _legacy_result_failed(result)
    if failure:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Failed to write recovery checkpoint: {failure}")
    if isinstance(result, dict) and result.get("ok") is False:
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Failed to write recovery checkpoint")
    return str(path)


def _commit_checkpoint(transaction_id: str) -> str | None:
    try:
        from .http import recovery_checkpoints_enabled
    except Exception:
        return None
    if not recovery_checkpoints_enabled():
        return None
    return _checkpoint_path(transaction_id)


def _apply_operation(operation: MutationOperation) -> Any:
    tool_name, argument_name, _scope = _OPERATION_TARGETS[operation.kind]
    arguments = operation.arguments
    if argument_name == "item":
        result = _legacy_call(tool_name, arguments)
    elif argument_name == "path":
        result = _legacy_call(tool_name, {"path": arguments.get("path", "")})
    else:
        result = _legacy_call(tool_name, {argument_name: arguments.get(argument_name, arguments.get("items", arguments))})
    failure = _legacy_result_failed(result)
    if failure:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"{operation.kind} failed: {failure}")
    return result


@idasync
def _mutation_before_state(operation: MutationOperation) -> Any:
    """Capture current names/comments/bytes so preview is useful for reversing."""

    try:
        import ida_bytes
        import ida_name
        import idaapi

        from .utils import parse_address
    except Exception:
        return None

    def _addr(item: Any) -> int | None:
        if not isinstance(item, dict):
            return None
        raw = item.get("addr") or item.get("ea") or item.get("func_addr")
        if raw is None:
            return None
        try:
            return parse_address(str(raw))
        except Exception:
            return None

    try:
        if operation.kind == "rename":
            before: dict[str, list[dict[str, str]]] = {}
            for group, items in operation.arguments.items():
                if not isinstance(items, list):
                    continue
                names = []
                for item in items:
                    ea = _addr(item)
                    if ea is None:
                        continue
                    names.append({"addr": hex(ea), "name": ida_name.get_name(ea) or ""})
                if names:
                    before[str(group)] = names
            return before or None
        if operation.kind in {"comment", "append_comment"}:
            items = operation.arguments.get("items") or operation.arguments.get("item") or []
            if isinstance(items, dict):
                items = [items]
            comments = []
            for item in items:
                ea = _addr(item)
                if ea is None:
                    continue
                comments.append({"addr": hex(ea), "comment": idaapi.get_cmt(ea, False) or ""})
            return comments or None
        if operation.kind in {"patch_bytes", "patch_asm", "write_integer"}:
            items = operation.arguments.get("items") or operation.arguments.get("patches") or []
            if isinstance(items, dict):
                items = [items]
            snapshots = []
            for item in items:
                ea = _addr(item)
                if ea is None:
                    continue
                size = max(1, min(int(item.get("size", 16) or 16), 64))
                snapshots.append({"addr": hex(ea), "bytes": ida_bytes.get_bytes(ea, size).hex() if ida_bytes.get_bytes(ea, size) else None})
            return snapshots or None
    except Exception:
        return None
    return None


@idasync
def _create_undo_point() -> bool:
    try:
        import ida_undo

        create = getattr(ida_undo, "create_undo_point", None)
        if create is None:
            return False
        try:
            return bool(create(b"ida-mcp", 7))
        except TypeError:
            pass
        try:
            return bool(create(b"ida-mcp"))
        except TypeError:
            pass
        # IDA 9.4+: create_undo_point(action_name: str, label: str).
        return bool(create("ida-mcp", "ida-mcp"))
    except Exception:
        return False


@idasync
def _perform_undo() -> bool:
    try:
        import ida_undo

        callback = getattr(ida_undo, "perform_undo", None)
        return bool(callback and callback())
    except Exception:
        return False


@idasync
def _debug_attach(pid: int, event_id: int = -1) -> dict[str, Any]:
    import ida_dbg

    result = int(ida_dbg.attach_process(int(pid), int(event_id)))
    if result <= 0:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Debugger attach failed with result {result}")
    return {"attached": True, "pid": int(pid), "result": result}


@idasync
def _debug_pause() -> dict[str, Any]:
    import ida_dbg

    if not ida_dbg.suspend_process():
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Debugger backend refused pause")
    return {"pause_requested": True}


@idasync
def _debug_add_watchpoints(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    import ida_dbg
    import idaapi
    from .utils import parse_address

    watch_types = {
        "write": idaapi.BPT_WRITE,
        "read": idaapi.BPT_READ,
        "readwrite": idaapi.BPT_RDWR,
        "execute": idaapi.BPT_EXEC,
    }
    results = []
    for item in items:
        address = str(item.get("addr", ""))
        kind = str(item.get("kind", "write")).lower()
        if kind not in watch_types:
            results.append({"addr": address, "error": f"Unsupported watchpoint kind: {kind}. Allowed: write, read, readwrite, execute"})
            continue
        try:
            ea = parse_address(address)
            size = max(1, int(item.get("size", 1)))
            ok = bool(ida_dbg.add_bpt(ea, size, watch_types[kind]))
            results.append({"addr": hex(ea), "kind": kind, "size": size, "ok": ok})
        except Exception as exc:
            results.append({"addr": address, "kind": kind, "error": str(exc)})
    return results


@idasync
def _debug_trace_action(action: str, options: dict[str, Any]) -> dict[str, Any]:
    import ida_dbg

    kind = str(options.get("kind", "instruction")).lower()
    toggles = {
        "instruction": (ida_dbg.enable_insn_trace, ida_dbg.disable_insn_trace, ida_dbg.is_insn_trace_enabled),
        "function": (ida_dbg.enable_func_trace, ida_dbg.disable_func_trace, ida_dbg.is_func_trace_enabled),
        "basic_block": (ida_dbg.enable_bblk_trace, ida_dbg.disable_bblk_trace, ida_dbg.is_bblk_trace_enabled),
        "step": (ida_dbg.enable_step_trace, ida_dbg.disable_step_trace, ida_dbg.is_step_trace_enabled),
    }
    if kind not in toggles:
        _unsupported("trace kind", options.get("kind", "instruction"), tuple(toggles))
    enable, disable, enabled = toggles[kind]
    if action == "start":
        if bool(options.get("clear", True)):
            ida_dbg.clear_trace()
        maximum = int(options.get("max_events", 10000))
        if maximum < 1 or maximum > 1_000_000:
            raise VNextError(ErrorCode.LIMIT_EXCEEDED, "max_events must be between 1 and 1000000")
        ida_dbg.set_trace_size(maximum)
        if not enable(True):
            raise VNextError(ErrorCode.NOT_SUPPORTED, f"Debugger backend cannot enable {kind} trace")
    elif action == "stop":
        disable()
    elif action not in {"status", "result"}:
        _unsupported("trace action", action, ("start", "status", "stop", "export", "result"))

    quantity = int(ida_dbg.get_tev_qty())
    offset = max(0, int(options.get("offset", 0)))
    limit = max(1, min(int(options.get("limit", 500)), 5000))
    event_types = {
        getattr(ida_dbg, "tev_none", 0): "none",
        getattr(ida_dbg, "tev_insn", 1): "instruction",
        getattr(ida_dbg, "tev_call", 2): "call",
        getattr(ida_dbg, "tev_ret", 3): "return",
        getattr(ida_dbg, "tev_bpt", 4): "breakpoint",
        getattr(ida_dbg, "tev_mem", 5): "memory",
        getattr(ida_dbg, "tev_event", 6): "event",
    }
    events = []
    for index in range(offset, min(quantity, offset + limit)):
        event_type = int(ida_dbg.get_tev_type(index))
        events.append(
            {
                "index": index,
                "type": event_types.get(event_type, str(event_type)),
                "addr": int(ida_dbg.get_tev_ea(index)),
                "thread_id": int(ida_dbg.get_tev_tid(index)),
            }
        )
    return {
        "kind": kind,
        "enabled": bool(enabled()),
        "event_count": quantity,
        "events": events,
        "truncated": offset + len(events) < quantity,
        "next_offset": offset + len(events) if offset + len(events) < quantity else None,
    }


@idasync
def _debug_trace_export(path: str, description: str) -> dict[str, Any]:
    import ida_dbg

    if not ida_dbg.save_trace_file(path, description):
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Debugger backend failed to save the trace")
    return {"path": path, "description": description, "saved": True}


@tool
def mutation_preview(
    operations: Annotated[
        list[dict[str, Any]],
        "Discriminated mutation operations. Each item needs kind plus either nested "
        "arguments or flat sibling fields (kind, addr, name). Examples: "
        "{kind, addr, name} or {kind, arguments: {addr, name}} for rename; "
        "{kind, addr, comment} for comment (text aliases comment); "
        "{kind, decl} for declare_type; {kind, addr, type} for set_type. "
        "Batch form: {kind: rename, arguments: {func: [{addr, name}]}} or "
        "{kind: comment, arguments: {items: [{addr, comment}]}}. "
        "kind is one of: rename, comment, append_comment, bookmark, declare_type, "
        "set_type, patch_bytes, write_integer, patch_asm, define_function, define_code, "
        "undefine, set_operand_type, make_data, declare_stack, delete_stack, save_database. "
        "Aliases set_name/rename_func map to rename.",
    ],
) -> dict[str, Any]:
    """WHEN staging any IDB change, use this; never call legacy mutators directly.
    RETURNS staged transaction with per-operation before/after and warnings.
    LIMITS rename dry-runs against legacy rename; other kinds are structural-only; commit requires the unchanged transaction id. NEXT mutation_status/mutation_commit."""

    parsed = _parse_operations(operations)
    for operation in parsed:
        if operation.kind != "rename":
            continue
        result = _legacy_call("rename", {"batch": {**operation.arguments, "dry_run": True}})
        detail = _legacy_result_failed(result)
        if detail is None and isinstance(result, dict) and result.get("ok") is False:
            detail = result.get("error") or "rename dry-run failed"
        if detail is not None:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"mutation_preview: rename dry-run failed: {detail}")
    preview = _TRANSACTIONS.preview(
        _database_id(),
        parsed,
        enabled_scopes=get_active_scopes(),
        preview_operation=lambda operation: {
            "kind": operation.kind,
            "arguments": operation.arguments,
            "validated": True,
            "before": _mutation_before_state(operation),
            "after": operation.arguments,
        },
    )
    result = preview.to_dict()
    try:
        from .http import recovery_checkpoints_enabled
    except Exception:
        recovery_checkpoints_enabled = None  # type: ignore[assignment]
    if recovery_checkpoints_enabled is not None and not recovery_checkpoints_enabled():
        warnings = list(result.get("warnings") or [])
        warnings.append("Recovery checkpoints are disabled; mutation_commit will not write a recovery IDB.")
        result["warnings"] = warnings
    return result


@tool
def mutation_commit(transaction_id: Annotated[str, "Preview transaction identifier"]) -> dict[str, Any]:
    """WHEN a staged transaction reviewed clean, use this; for state checks use mutation_status.
    RETURNS the commit receipt with recovery outcome.
    LIMITS commits the unchanged preview only; recovery checkpoints only when the dashboard option enables them. NEXT mutation_rollback on regret."""

    receipt = _TRANSACTIONS.commit(
        transaction_id,
        database=_database_id(),
        enabled_scopes=get_active_scopes(),
        checkpoint=_commit_checkpoint,
        apply_operation=_apply_operation,
        undo=_perform_undo,
        begin=_create_undo_point,
    )
    return receipt.to_dict()


@tool
def mutation_status(transaction_id: Annotated[str, "Transaction identifier"]) -> dict[str, Any]:
    """WHEN following a staged transaction, use this instead of re-previewing.
    RETURNS preview or committed transaction state.
    LIMITS read-only view; expired transactions raise TRANSACTION_EXPIRED. NEXT mutation_commit/mutation_rollback."""

    return _TRANSACTIONS.status(transaction_id)


@tool
def mutation_rollback(transaction_id: Annotated[str, "Committed transaction identifier"]) -> dict[str, Any]:
    """WHEN undoing the latest commit, use this; older transactions are rejected.
    RETURNS the rollback receipt.
    LIMITS latest committed transaction only; without a checkpoint it uses native undo, else raises REOPEN_REQUIRED with the checkpoint path. NEXT re-preview corrections via mutation_preview."""

    return _TRANSACTIONS.rollback(transaction_id, rollback_undo=_perform_undo).to_dict()


@tool
def debug_session(action: Annotated[DebugSessionAction, "start, attach, detach, terminate, or status"], target: Annotated[dict[str, Any] | None, "Process launch or attach target"] = None) -> dict[str, Any]:
    """WHEN driving the debugger process, use this; for stepping use debug_control.
    RETURNS {data} envelope with the legacy backend result.
    LIMITS capability-gated; attach needs target.pid; start/terminate/detach delegate to dbg_start/dbg_exit/dbg_detach. NEXT debug_control/debug_breakpoints once running."""

    mapping = {"start": "dbg_start", "status": "dbg_status", "terminate": "dbg_exit", "detach": "dbg_detach"}
    normalized = str(action).lower()
    if normalized == "attach":
        pid = (target or {}).get("pid")
        if pid is None:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Attach requires target.pid")
        return ToolEnvelope(_debug_attach(int(pid), int((target or {}).get("event_id", -1)))).to_dict()
    name = mapping.get(normalized)
    if name is None:
        _unsupported("debug session action", action, get_args(DebugSessionAction))
    return ToolEnvelope(_legacy_call(name, target or {}), provenance={"legacy_tool": name}).to_dict()


@tool
def debug_control(action: Annotated[DebugControlAction, "continue, step_into, step_over, pause, or run_to"], addr: Annotated[str | None, "Run-to address"] = None) -> dict[str, Any]:
    """WHEN the session runs, use this; for lifecycle use debug_session.
    RETURNS {data} envelope with the backend step result.
    LIMITS pause runs locally; run_to needs addr; other actions delegate to dbg_continue/dbg_step_into/dbg_step_over/dbg_run_to. NEXT debug_state to read the stopped state."""

    mapping = {"continue": "dbg_continue", "step_into": "dbg_step_into", "step_over": "dbg_step_over", "run_to": "dbg_run_to"}
    normalized = str(action).lower()
    if normalized == "pause":
        return ToolEnvelope(_debug_pause()).to_dict()
    name = mapping.get(normalized)
    if name is None:
        _unsupported("debugger control", action, get_args(DebugControlAction))
    return ToolEnvelope(_legacy_call(name, {"addr": addr} if normalized == "run_to" else {}), provenance={"legacy_tool": name}).to_dict()


@tool
def debug_breakpoints(action: Annotated[DebugBreakpointAction, "list, add, delete, toggle, or watch"], items: Annotated[list[dict[str, Any]] | list[str] | None, "Breakpoint addresses or records"] = None) -> dict[str, Any]:
    """WHEN stopping places matter, use this; for stepping use debug_control.
    RETURNS {data} envelope with the backend breakpoint result.
    LIMITS list/add/delete/toggle delegate to dbg_bps/dbg_add_bp/dbg_delete_bp/dbg_toggle_bp; watch needs record items and runs locally. NEXT debug_control to run to them."""

    effective_items = list(items or [])
    normalized = str(action).lower()
    if normalized == "watch":
        if not all(isinstance(item, dict) for item in effective_items):
            raise VNextError(ErrorCode.INVALID_OPERATION, "Watchpoints require record items")
        return ToolEnvelope(_debug_add_watchpoints(effective_items)).to_dict()
    mapping = {"list": ("dbg_bps", {}), "add": ("dbg_add_bp", {"addrs": effective_items}), "delete": ("dbg_delete_bp", {"addrs": effective_items}), "toggle": ("dbg_toggle_bp", {"items": effective_items})}
    if normalized not in mapping:
        _unsupported("breakpoint action", action, get_args(DebugBreakpointAction))
    name, arguments = mapping[normalized]
    return ToolEnvelope(_legacy_call(name, arguments), provenance={"legacy_tool": name}).to_dict()


@tool
def debug_state(include: Annotated[list[str] | None, "registers, stack, breakpoints, or status"] = None) -> dict[str, Any]:
    """WHEN reading stopped state, use this instead of individual dbg_* tools.
    RETURNS {data} envelope keyed by the requested sections.
    LIMITS sections are status/registers/stack/breakpoints (default status+registers+stack); each delegates to one legacy dbg_* read. NEXT debug_control to resume."""
    effective = [str(item).lower() for item in (include if include is not None else ["status", "registers", "stack"])]
    result: dict[str, Any] = {}
    mapping = {"status": "dbg_status", "registers": "dbg_regs", "stack": "dbg_stacktrace", "breakpoints": "dbg_bps"}
    for item in effective:
        if item not in mapping:
            _unsupported("debugger state section", item, ("status", "registers", "stack", "breakpoints"))
        result[item] = _legacy_call(mapping[item], {})
    return ToolEnvelope(result).to_dict()


@tool
def debug_memory(action: Annotated[DebugMemoryAction, "read, write, snapshot, or diff"], regions: Annotated[list[dict[str, Any]] | None, "Live memory regions"] = None, confirm_nonrollbackable: Annotated[bool, "Required for writes"] = False, snapshot_id: Annotated[str | None, "Snapshot identifier for diff"] = None) -> dict[str, Any]:
    """WHEN live process bytes matter, use this; for static bytes use memory_read.
    RETURNS {data} envelope; snapshot returns {snapshot_id, regions, value}, diff returns {snapshot_id, changed, before, after}.
    LIMITS writes need confirm_nonrollbackable=true and are non-rollbackable; snapshots are per-database. NEXT debug_state for registers/stack."""
    normalized = str(action).lower()
    effective_regions = list(regions or [])
    if normalized == "read":
        return ToolEnvelope(_legacy_call("dbg_read", {"regions": effective_regions}), provenance={"legacy_tool": "dbg_read"}).to_dict()
    if normalized == "write":
        if not confirm_nonrollbackable:
            raise VNextError(ErrorCode.PROFILE_DENIED, "Live-memory writes require confirm_nonrollbackable=true")
        return ToolEnvelope(_legacy_call("dbg_write", {"regions": effective_regions}), provenance={"legacy_tool": "dbg_write"}).to_dict()
    if normalized == "snapshot":
        value = _legacy_call("dbg_read", {"regions": effective_regions})
        identifier = str(uuid4())
        _DEBUG_SNAPSHOTS[identifier] = {"database": _database_id(), "regions": effective_regions, "value": value}
        return ToolEnvelope({"snapshot_id": identifier, "regions": effective_regions, "value": value}).to_dict()
    if normalized == "diff":
        if not snapshot_id or snapshot_id not in _DEBUG_SNAPSHOTS:
            raise VNextError(ErrorCode.INVALID_OPERATION, "A valid snapshot_id is required")
        previous = _DEBUG_SNAPSHOTS[snapshot_id]
        if previous["database"] != _database_id():
            raise VNextError(ErrorCode.INVALID_DATABASE, "Snapshot belongs to another database")
        current = _legacy_call("dbg_read", {"regions": effective_regions or previous["regions"]})
        return ToolEnvelope(
            {
                "snapshot_id": snapshot_id,
                "changed": current != previous["value"],
                "before": previous["value"],
                "after": current,
            }
        ).to_dict()
    _unsupported("debug memory action", action, get_args(DebugMemoryAction))

@tool
def debug_trace(action: Annotated[DebugTraceAction, "start, status, stop, or export"], options: Annotated[DebugTraceOptions | None, "Trace limits and export options"] = None) -> dict[str, Any]:
    """WHEN single-stepping history matters, use this; for static flow use dataflow_trace.
    RETURNS {kind, enabled, event_count, events, truncated, next_offset} dict.
    LIMITS kind is instruction/function/basic_block/step; status paginates by options.offset/limit (max 5000); export needs filesystem scope and options.path. NEXT debug_memory/debug_state for the stopped state."""
    normalized = str(action).lower()
    if normalized not in get_args(DebugTraceAction):
        _unsupported("debug trace action", action, get_args(DebugTraceAction))
    effective = dict(options or {})
    if normalized == "export":
        if SafetyScope.FILESYSTEM not in get_active_scopes():
            raise VNextError(ErrorCode.PROFILE_DENIED, "Trace export requires filesystem scope")
        path = effective.get("path")
        if not path:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Trace export requires options.path")
        output = get_workspace_policy().resolve(str(path), must_exist=False)
        return ToolEnvelope(
            _debug_trace_export(str(output), str(effective.get("description", "ida-pro-mcp trace")))
        ).to_dict()
    return ToolEnvelope(_debug_trace_action(normalized, effective)).to_dict()


@tool
def python_execute(mode: Annotated[PythonExecuteMode, "eval or file"], code: Annotated[str | None, "Python expression or statements"] = None, path: Annotated[str | None, "Python file path"] = None) -> dict[str, Any]:
    """WHEN no canonical tool covers the need, use this escape hatch; prefer typed tools first.
    RETURNS {data} envelope with the backend execution result.
    LIMITS python safety scope gates both modes; eval needs code, file needs path plus filesystem scope and audit redaction. NEXT investigation_add_finding to record anything learned."""
    normalized = str(mode).lower()
    if normalized not in get_args(PythonExecuteMode):
        _unsupported("python execute mode", mode, get_args(PythonExecuteMode))
    if normalized == "eval" and code is not None:
        return ToolEnvelope(_legacy_call("py_eval", {"code": code}), provenance={"legacy_tool": "py_eval"}).to_dict()
    if normalized == "file" and path is not None:
        if SafetyScope.FILESYSTEM not in get_active_scopes():
            raise VNextError(ErrorCode.PROFILE_DENIED, "Python file execution also requires filesystem scope")
        safe_path = get_workspace_policy().resolve(path, must_exist=True)
        return ToolEnvelope(_legacy_call("py_exec_file", {"file_path": str(safe_path)}), provenance={"legacy_tool": "py_exec_file"}).to_dict()
    raise VNextError(ErrorCode.INVALID_OPERATION, "python_execute requires code for eval or path for file")


@resource("ida://server/capabilities")
def capabilities_resource() -> dict[str, Any]:
    """Versioned server and runtime capability manifest."""

    return server_capabilities()


def _validate_resource_database(database: str) -> str:
    decoded = unquote(database)
    current = _database_id()
    if decoded not in {"active", current, get_current_transport_session_id()}:
        raise VNextError(
            ErrorCode.INVALID_DATABASE,
            "Resource belongs to another database",
            details={"requested": decoded, "active": current},
        )
    return current


@resource("ida://sessions")
def sessions_resource() -> dict[str, Any]:
    """List the active runtime-local database session."""

    manifest = server_capabilities()
    return {"sessions": [manifest] if manifest.get("database") else [], "count": 1 if manifest.get("database") else 0}


@resource("ida://sessions/{database}/metadata")
def session_metadata_resource(database: str) -> dict[str, Any]:
    """Return versioned IDB metadata, capability, and revision information."""

    _validate_resource_database(database)
    from .api_resources import idb_metadata_resource

    return {"metadata": idb_metadata_resource(), "capabilities": server_capabilities()}


@resource("ida://sessions/{database}/jobs")
def jobs_resource(database: str) -> dict[str, Any]:
    """List persisted jobs for one database session."""

    current = _validate_resource_database(database)
    records = _jobs().list(database=current)
    return {"jobs": records, "count": len(records)}


@resource("ida://sessions/{database}/jobs/{job_id}")
def job_resource(database: str, job_id: str) -> dict[str, Any]:
    """Current state of a job belonging to a database session."""

    current = _validate_resource_database(database)
    value = _jobs().status(job_id, include_result=False)
    if value.get("database") not in {None, current}:
        raise VNextError(ErrorCode.INVALID_DATABASE, "Job belongs to another database")
    return value


@resource("ida://sessions/{database}/investigations")
def investigations_resource(database: str) -> dict[str, Any]:
    """List persisted investigations for one database session."""

    current = _validate_resource_database(database)
    records = _investigations().list(database=current)
    return {"investigations": records, "count": len(records)}


@resource("ida://sessions/{database}/investigations/{investigation_id}")
def investigation_resource(database: str, investigation_id: str) -> dict[str, Any]:
    """Persisted investigation findings for a database session."""

    current = _validate_resource_database(database)
    value = _investigations().get(investigation_id).to_dict()
    if value.get("database") not in {None, current}:
        raise VNextError(ErrorCode.INVALID_DATABASE, "Investigation belongs to another database")
    return value


@resource("ida://sessions/{database}/debugger")
def debugger_resource(database: str) -> dict[str, Any]:
    """Return the current debugger state when a backend is available."""

    _validate_resource_database(database)
    if not _ida_capabilities().debugger_available:
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Debugger backend is unavailable")
    return debug_state()


@resource("ida://sessions/{database}/audit")
def session_audit_resource(database: str) -> dict[str, Any]:
    """Return local redacted audit history for a database session."""

    _validate_resource_database(database)
    return audit_resource()


@resource("ida://audit")
def audit_resource() -> dict[str, Any]:
    """Local redacted audit history for the current server process."""

    return {"records": MCP_AUDIT.records()}


def _prompt(objective: str, workflow: str, database: str = "") -> str:
    database_line = f"Use database session `{database}`. " if database else ""
    return f"{database_line}Objective: {objective}\n\nWorkflow:\n{workflow}\n\nCite addresses and tool evidence; label uncertainty explicitly."


@prompt
def triage_binary(database: str = "") -> str:
    """Systematic first-pass binary triage."""

    return _prompt("Triage the binary and identify the highest-value analysis targets.", "1. Read capabilities and metadata.\n2. Run analysis_run in triage mode.\n3. Rank imports, strings, entrypoints, and suspicious functions.\n4. Create an investigation for deeper work.", database)


@prompt
def explain_function(target: str, database: str = "") -> str:
    """Evidence-backed function explanation."""

    return _prompt(f"Explain function {target}.", "Decompile and disassemble it, inspect callers/callees and data references, then summarize inputs, outputs, side effects, and confidence.", database)


@prompt
def trace_input_to_sink(source: str, sink: str, database: str = "") -> str:
    """Trace a source toward a security-relevant sink."""

    return _prompt(f"Trace {source} to {sink}.", "Run dataflow_trace and taint_analyze. Distinguish microcode def-use from reference-flow fallback and preserve all supporting addresses.", database)


@prompt
def deobfuscate_component(targets: str, database: str = "") -> str:
    """Plan evidence-preserving deobfuscation."""

    return _prompt(f"Analyze obfuscation around {targets}.", "Identify the transformation, document invariants, stage all IDB changes through mutation_preview, and do not commit without explicit approval.", database)


@prompt
def review_patch(transaction_id: str, database: str = "") -> str:
    """Review a staged mutation before commit."""

    return _prompt(f"Review mutation transaction {transaction_id}.", "Read mutation_status, verify every before/after change and warning, assess recovery checkpoint requirements, then recommend commit or rejection.", database)


@prompt
def generate_report(investigation_id: str, format: str = "markdown", database: str = "") -> str:
    """Generate an evidence-backed investigation report."""

    return _prompt(f"Generate a {format} report for investigation {investigation_id}.", "Verify findings and evidence, identify unresolved hypotheses, and call investigation_export only after the record is complete.", database)


_install_revision_hook()
_install_debug_hook()
