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
import re
import sys
from pathlib import Path
from threading import RLock
from typing import Annotated, Any, Callable, Literal, NoReturn, TypedDict, get_args
from urllib.parse import quote, unquote
from uuid import uuid4

from ida_pro_mcp.vnext.analysis import normalize_reference_flow_graph
from ida_pro_mcp.vnext.contracts import (
    AnalysisEngine,
    AnalysisGraph,
    CapabilityManifest,
    ErrorCode,
    MutationOperation,
    MutationPreview,
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
SearchKind = Literal["text", "regex", "bytes", "constant", "instruction", "crypto", "ctree"]
MemoryReadKind = Literal["bytes", "integer", "string", "global", "struct", "patch_diff"]
AnalysisMode = Literal["triage", "function", "component", "batch", "similar", "deep", "emulate"]
GraphKind = Literal["xrefs", "xrefs_from", "xrefs_both", "calls", "callers", "path", "field_xrefs", "cfg", "callsite_args"]
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


class SearchOptions(TypedDict, total=False):
    case_sensitive: Annotated[bool, "text/regex: case-sensitive match (default false)"]
    include: Annotated[
        Literal["all", "disasm", "comments", "strings"],
        "text/regex: all = listing lines + comments (default), disasm, comments, or strings = defined string literals only",
    ]
    code_only: Annotated[bool, "text/regex: skip non-executable segments (default false)"]
    start: Annotated[str, "text/regex/instruction: lower bound address"]
    end: Annotated[str, "text/regex/instruction: exclusive upper bound address"]
    func: Annotated[str, "text/regex/instruction: restrict to one function (name or address)"]
    segment: Annotated[str, "text/regex/instruction: restrict to one segment by name, e.g. .text"]


class AnalysisOptions(TypedDict, total=False):
    detail_level: Annotated[str, "triage verbosity: fast (default) or full"]
    include_asm: Annotated[bool, "function mode: include disassembly"]
    include_declarations: Annotated[bool, "function/batch: keep local-variable declarations in the decompile excerpt (default false)"]
    include_comments: Annotated[bool, "function mode: include instruction comments; IDA auto-comments are included (default false)"]
    max_lines: Annotated[int, "function/batch: statement lines in the decompile excerpt (default 120)"]
    sections: Annotated[
        list[str],
        "batch mode: subset of decompile, disasm, callers, callees, strings, constants, blocks (default decompile, callees, strings)",
    ]
    skip_triage: Annotated[bool, "deep mode: skip the whole-binary triage (default true when targets are given)"]
    max_depth: Annotated[int, "deep mode: reference-flow depth per target (1-20)"]
    direction: Annotated[str, "deep mode: dataflow direction forward, backward, or both"]
    limit: Annotated[int, "similar mode: maximum matches"]
    min_score: Annotated[float, "similar mode: minimum similarity score 0-1"]
    calls: Annotated[
        list[list[Any]],
        "emulate mode: one argument list per call; each arg is an int, address/name string, "
        "or {bytes: hex} / {string: text} / {wstring: text} / {buffer: size} placed on the emulator heap",
    ]
    max_insns: Annotated[int, "emulate mode: instruction budget per call (default 2000000)"]
    timeout_ms: Annotated[int, "emulate mode: wall-clock budget per call (default 10000)"]


class GraphOptions(TypedDict, total=False):
    xref_type: Annotated[Literal["any", "code", "data"], "xrefs/xrefs_from/xrefs_both: reference type filter (default any)"]
    include_indirect: Annotated[
        bool,
        "calls/callers/path: follow resolved indirect calls and list unresolved indirect sites / address-taken references (default true)",
    ]
    max_edges_per_func: Annotated[int, "calls/callers/path: distinct callees or callers kept per function (1-5000, default 100)"]
    max_paths: Annotated[int, "path: maximum shortest paths returned (1-1000, default 10)"]


TaintDomain = Literal["register", "stack", "global", "memory"]


class TaintOptions(TypedDict, total=False):
    max_paths: Annotated[int, "maximum reported hits (1-1000, default 100)"]
    domains: Annotated[list[TaintDomain], "location kinds propagation may pass through (default all)"]


class DataflowOptions(TypedDict, total=False):
    include_microcode: Annotated[bool, "add each node's raw Hex-Rays microcode (default false)"]


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
    max_lines: Annotated[int, "per-seed decompile excerpt statement lines (default 120)"]
    max_seeds: Annotated[int, "seeds analyzed, 1-100 (default 20); the rest are listed in skipped_seeds"]
    skip_triage: Annotated[bool, "skip the whole-binary triage (default false)"]


MutationKind = Literal[
    "rename", "comment", "append_comment", "bookmark", "declare_type", "set_type", "upsert_enum",
    "declare_stack", "delete_stack", "patch_bytes", "write_integer", "patch_asm", "define_function",
    "define_code", "undefine", "set_operand_type", "make_data", "apply_flirt", "load_til", "save_database",
    "set_name", "rename_func", "rename_function", "rename_global", "rename_data", "enum_upsert",
]


class _MutationOpKind(TypedDict):
    kind: MutationKind


class MutationOp(_MutationOpKind, total=False):
    arguments: Annotated[dict[str, Any], "nested form of the fields below"]
    scope: Annotated[str, "raise the required safety scope"]
    addr: Annotated[str, "hex address or symbol"]
    name: str
    comment: str
    text: Annotated[str, "alias of comment"]
    type: Annotated[str, "C type or prototype; __noreturn in a prototype marks the function no-return"]
    decl: Annotated[str | list[str], "C declaration(s)"]
    variable: Annotated[str, "set_type: local variable"]
    old_name: str
    new_name: str
    func_addr: str
    allow_overwrite: bool
    members: Annotated[list[dict[str, Any]], "upsert_enum [{name, value}]"]
    bitfield: bool
    offset: Annotated[str | int, "declare_stack frame offset, e.g. -8"]
    data: Annotated[str | list[dict[str, Any]], "patch_bytes hex bytes"]
    value: Annotated[str, "write_integer value"]
    ty: Annotated[str, "write_integer width (u8/u32/i64...)"]
    size: int
    asm: str
    end: Annotated[str, "define_function end; on an existing function, resizes it"]
    op_n: int
    operand_kind: Literal["stroff", "offset", "stkvar", "hex", "dec", "char", "binary", "octal", "enum"]
    struct: str
    enum: str
    delta: int
    target_addr: str
    prefix: Annotated[str, "bookmark title prefix"]
    path: str
    items: Annotated[list[dict[str, Any]], "batch of flat items for this kind"]


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
        if _JOBS is not None:
            return _JOBS
    # Netnode reads hop to the main thread, whose closebase hook takes
    # _STATE_LOCK: never load while holding it.
    state = _load_idb_state("jobs")
    with _STATE_LOCK:
        if _JOBS is None:
            _JOBS = JobManager(
                max_workers=2,
                max_jobs=256,
                load_state=lambda: state,
                save_state=lambda state: _save_idb_state("jobs", state),
                on_change=_job_changed,
            )
        return _JOBS


def _investigations() -> InvestigationManager:
    global _INVESTIGATIONS
    with _STATE_LOCK:
        if _INVESTIGATIONS is not None:
            return _INVESTIGATIONS
    state = _load_idb_state("investigations")
    with _STATE_LOCK:
        if _INVESTIGATIONS is None:
            _INVESTIGATIONS = InvestigationManager(
                load_state=lambda: state,
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
    if event == "renamed":
        try:
            from .utils import invalidate_name_index

            invalidate_name_index()
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


def _search_cursor_states(cursor: str | None, kind: str, count: int) -> list[dict[str, Any] | None]:
    """Per-target continuation states; a cursor is bound to its search kind and target count."""
    if not cursor:
        return [{} for _ in range(count)]
    value = _decode_cursor_value(cursor)
    if value.get("kind") != kind:
        raise VNextError(
            ErrorCode.INVALID_OPERATION,
            f"Cursor belongs to search kind {value.get('kind')!r}, not {kind!r}; omit cursor to start over",
        )
    states = value.get("states")
    if not isinstance(states, list) or len(states) != count or not all(s is None or isinstance(s, dict) for s in states):
        raise VNextError(ErrorCode.INVALID_OPERATION, "Cursor does not match targets; pass the same targets as the first call")
    return states


def _search_cursor(kind: str, states: list[dict[str, Any] | None]) -> str | None:
    if all(state is None for state in states):
        return None
    return _encode_cursor_value({"kind": kind, "states": states})


def _state_offset(state: dict[str, Any]) -> int:
    try:
        return max(0, int(state.get("offset", 0)))
    except (TypeError, ValueError) as exc:
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


_INSTRUCTION_SCAN_BUDGET = 200000
_INSTRUCTION_FILTERS = {"op0": "op0", "op1": "op1", "op2": "op2", "any": "op_any"}


def _parse_instruction_target(target: str) -> dict[str, Any]:
    """`mnem op0=x op1=x op2=x any=x` -> insn_query filters (int = operand value, else operand-text substring)."""
    tokens = str(target).split()
    query: dict[str, Any] = {"mnem": ""}
    if tokens and "=" not in tokens[0]:
        mnem = tokens.pop(0).lower()
        query["mnem"] = "" if mnem in ("*", "any") else mnem
    for token in tokens:
        key, sep, value = token.partition("=")
        field = _INSTRUCTION_FILTERS.get(key.lower())
        if not sep or field is None or not value:
            raise VNextError(
                ErrorCode.INVALID_OPERATION,
                f"Bad instruction filter {token!r}; use 'mnem op0=<text|int> op1=... op2=... any=...'",
            )
        try:
            query[field] = int(value, 0)
        except ValueError:
            query[f"{field}_text"] = value
    return query


def _text_hit(hit: dict[str, Any]) -> dict[str, Any]:
    row = {"addr": hit.get("addr")}
    if hit.get("function"):
        row["function"] = hit["function"]
    for match in hit.get("matches") or []:
        row.setdefault("comment" if match.get("kind") == "comment" else "text", match.get("text"))
    return row


def _hit_rows_impl(addrs: list[str]) -> list[dict[str, Any]]:
    """{addr, function?, text?} for raw hit addresses; text only for code heads."""
    import ida_bytes

    from . import compat
    from .utils import disasm_text, display_name

    rows = []
    for addr in addrs:
        ea = int(str(addr), 16)
        row: dict[str, Any] = {"addr": hex(ea)}
        func = compat.get_func(ea)
        if func is not None:
            row["function"] = display_name(func.start_ea)
        if ida_bytes.is_code(ida_bytes.get_flags(ea)) and ida_bytes.get_item_head(ea) == ea:
            row["text"] = disasm_text(ea)
        rows.append(row)
    return rows


_hit_rows = idasync(_hit_rows_impl)


def _search_bounds_impl(options: dict[str, Any]) -> tuple[str, str]:
    """Resolve options.func/segment/start/end to a hex [start, end) pair ("" = unbounded)."""
    import ida_segment

    from . import compat
    from .utils import parse_address

    if options.get("func"):
        func = compat.get_func(parse_address(options["func"]))
        if func is None:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"Not inside a function: {options['func']}")
        return hex(func.start_ea), hex(func.end_ea)
    if options.get("segment"):
        seg = ida_segment.get_segm_by_name(str(options["segment"]))
        if seg is None:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"Unknown segment: {options['segment']}")
        return hex(seg.start_ea), hex(seg.end_ea)
    start = hex(parse_address(options["start"])) if options.get("start") else ""
    end = hex(parse_address(options["end"])) if options.get("end") else ""
    return start, end


_search_bounds = idasync(_search_bounds_impl)


def _search_text_targets(
    kind: str, targets: list[str], states: list[dict[str, Any] | None], limit: int, options: dict[str, Any], bounds: tuple[str, str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any] | None]]:
    include = str(options.get("include") or "all").lower()
    if include not in ("all", "disasm", "comments", "strings"):
        raise VNextError(ErrorCode.INVALID_OPERATION, f"Unknown include {include!r}. Allowed: all, disasm, comments, strings")
    case_sensitive = bool(options.get("case_sensitive", False))
    start, end = bounds
    data: list[dict[str, Any]] = []
    next_states: list[dict[str, Any] | None] = []
    for target, state in zip(targets, states):
        if state is None:
            next_states.append(None)
            continue
        if include == "strings":
            query: dict[str, Any] = {
                "kind": "strings",
                "regex": target if kind == "regex" else re.escape(target),
                "case_sensitive": case_sensitive,
                "offset": _state_offset(state),
                "count": limit,
            }
            if start:
                query["min_addr"] = start
            if end:
                query["max_addr"] = hex(int(end, 16) - 1)
            page = _legacy_call("entity_query", {"queries": query})[0]
            row: dict[str, Any] = {"target": target, "matches": [{"addr": r["addr"], "text": r["text"]} for r in page["data"]]}
            if page.get("error"):
                row["error"] = page["error"]
            next_states.append({"offset": page["next_offset"]} if page.get("next_offset") is not None else None)
        else:
            result = _legacy_call(
                "search_text",
                {
                    "pattern": target,
                    "limit": limit,
                    "start": state.get("start") or start,
                    "end": end,
                    "regex": kind == "regex",
                    "case_sensitive": case_sensitive,
                    "include": include,
                    "code_only": bool(options.get("code_only", False)),
                },
            )
            row = {"target": target, "matches": [_text_hit(hit) for hit in result.get("hits") or []]}
            if result.get("error"):
                row["error"] = result["error"]
            if result.get("partial"):
                row["partial"] = result.get("reason")
            resume = (result.get("cursor") or {}).get("next")
            next_states.append({"start": resume} if resume else None)
        data.append(row)
    return data, next_states


def _search_offset_targets(
    kind: str, targets: list[str], states: list[dict[str, Any] | None], limit: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any] | None]]:
    data: list[dict[str, Any]] = []
    next_states: list[dict[str, Any] | None] = []
    for target, state in zip(targets, states):
        if state is None:
            next_states.append(None)
            continue
        offset = _state_offset(state)
        if kind == "bytes":
            result = _legacy_call("find_bytes", {"patterns": [target], "limit": limit, "offset": offset})[0]
        else:
            result = _legacy_call("find", {"type": "immediate", "targets": [target], "limit": limit, "offset": offset})[0]
        addrs = result.get("matches") or []
        row: dict[str, Any] = {"target": target, "matches": _hit_rows(addrs) if addrs else []}
        if result.get("error"):
            row["error"] = result["error"]
        resume = (result.get("cursor") or {}).get("next")
        next_states.append({"offset": int(resume)} if resume is not None else None)
        data.append(row)
    return data, next_states


def _search_instruction_targets(
    targets: list[str], states: list[dict[str, Any] | None], limit: int, bounds: tuple[str, str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any] | None]]:
    start, end = bounds
    pending = [(target, state) for target, state in zip(targets, states) if state is not None]
    queries = []
    for target, state in pending:
        query = {
            **_parse_instruction_target(target),
            "offset": _state_offset(state),
            "count": limit,
            "max_scan_insns": _INSTRUCTION_SCAN_BUDGET,
            "allow_broad": True,
        }
        if state.get("start") or start:
            query["start"] = state.get("start") or start
        if end:
            query["end"] = end
        queries.append(query)
    results = iter(_legacy_call("insn_query", {"queries": queries}) if queries else [])
    data: list[dict[str, Any]] = []
    next_states: list[dict[str, Any] | None] = []
    for target, state in zip(targets, states):
        if state is None:
            next_states.append(None)
            continue
        item = next(results)
        addrs = [match["addr"] for match in item.get("matches") or []]
        row: dict[str, Any] = {"target": target, "matches": _hit_rows(addrs) if addrs else []}
        if item.get("error"):
            row["error"] = item["error"]
        resume = (item.get("cursor") or {}).get("next")
        if item.get("truncated") and item.get("next_start"):
            row["partial"] = "scan_budget"
            next_states.append({"offset": 0, "start": str(item["next_start"])})
        elif resume is not None:
            next_states.append({"offset": int(resume), **({"start": state["start"]} if state.get("start") else {})})
        else:
            next_states.append(None)
        data.append(row)
    return data, next_states


@tool
def search(
    kind: Annotated[SearchKind, "text, regex, bytes, constant, instruction, crypto, or ctree"],
    targets: Annotated[list[str], "Patterns; each target is searched and paged independently"],
    limit: Annotated[int, "Maximum matches per target per page"] = 100,
    cursor: Annotated[str | None, "next_cursor from the previous call (same kind and targets)"] = None,
    options: Annotated[SearchOptions | None, "Matching and scope options for text/regex/instruction"] = None,
) -> dict[str, Any]:
    """Find where text, bytes, constants, instructions, crypto tables, or Hex-Rays patterns occur.
    WHEN: locating occurrences; to list entities use entity_query.
    RETURNS {data, next_cursor?}. text/regex/bytes/constant/instruction: [{target, matches[{addr, function?, text?, comment?}], error?, partial?}] per unfinished target. crypto: {matches, total}. ctree: one page per pattern.
    LIMITS: text (literal) and regex search disassembly and comments (options.include="strings" for string literals); constant matches any operand width. instruction: "mnem op0=x any=x" (int = operand value, else operand-text substring, "*" = any mnemonic). bytes: "48 8B ?? ??". ctree tokens: op=call|cmp|num, callee=, argN=, value=, in=. Resume partial pages with the cursor (same kind and targets).
    NEXT: decompile the hit's function; graph_query(kind="xrefs") on hits."""
    normalized = str(kind).lower()
    if normalized not in get_args(SearchKind):
        _unsupported("search kind", kind, get_args(SearchKind))
    opts: dict[str, Any] = dict(options or {})
    scoped = any(opts.get(key) for key in ("func", "segment", "start", "end"))
    if scoped and normalized not in ("text", "regex", "instruction"):
        raise VNextError(ErrorCode.INVALID_OPERATION, f"options func/segment/start/end apply only to text/regex/instruction, not {normalized}")
    bounds = _search_bounds(opts) if scoped else ("", "")
    if normalized in ("text", "regex"):
        states = _search_cursor_states(cursor, normalized, len(targets))
        data, next_states = _search_text_targets(normalized, targets, states, limit, opts, bounds)
    elif normalized in ("bytes", "constant"):
        states = _search_cursor_states(cursor, normalized, len(targets))
        data, next_states = _search_offset_targets(normalized, targets, states, limit)
    elif normalized == "instruction":
        states = _search_cursor_states(cursor, normalized, len(targets))
        data, next_states = _search_instruction_targets(targets, states, limit, bounds)
    elif normalized == "crypto":
        from . import api_recovery

        (state,) = _search_cursor_states(cursor, normalized, 1)
        offset = _state_offset(state or {})
        rows = idasync(api_recovery.collect_crypto_constants)(targets)
        data = {"matches": rows[offset : offset + limit], "total": len(rows)}
        next_states = [{"offset": offset + limit} if len(rows) > offset + limit else None]
    else:
        from .hexrays_ctree import pattern_search

        states = _search_cursor_states(cursor, normalized, len(targets))
        data, next_states = [], []
        for target, state in zip(targets, states):
            if state is None:
                next_states.append(None)
                continue
            page = pattern_search(target, _state_offset(state), limit)
            data.append(page)
            next_states.append({"offset": page["next_offset"]} if page.get("next_offset") is not None else None)
    next_cursor = _search_cursor(normalized, next_states)
    return ToolEnvelope(data, truncated=next_cursor is not None, next_cursor=next_cursor).to_dict()


_INT_SHORTHAND = re.compile(r"^(.+):([ui](?:nt)?(?:8|16|32|64)(?:_t)?(?:le|be)?)$", re.IGNORECASE)


def _normalize_memory_queries(kind: str, queries: list[dict[str, Any]] | list[str]) -> list[Any]:
    """Normalize memory_read queries to the row shapes the readers expect."""
    if kind in ("bytes", "integer", "struct"):
        normalized: list[Any] = []
        for item in queries:
            if isinstance(item, dict):
                normalized.append(item)
            elif isinstance(item, str):
                shorthand = _INT_SHORTHAND.match(item.strip()) if kind == "integer" else None
                normalized.append({"addr": shorthand[1], "ty": shorthand[2]} if shorthand else {"addr": item})
            else:
                raise VNextError(ErrorCode.INVALID_OPERATION, f"{kind} queries must be address strings or objects")
        return normalized
    # string / global accept bare address/name strings.
    return list(queries)


def _compact_memory_row(kind: str, row: Any) -> Any:
    if not isinstance(row, dict):
        return row
    if kind == "bytes" and not row.get("error") and row.get("data") is not None:
        raw = bytes(int(part, 16) for part in str(row["data"]).split())
        return {"addr": row.get("addr"), "size": len(raw), "hex": raw.hex()}
    return {key: value for key, value in row.items() if not (key in ("error", "data") and value is None)}


@tool
def memory_read(
    kind: Annotated[MemoryReadKind, "bytes, integer, string, global, struct, or patch_diff"],
    queries: Annotated[
        list[dict[str, Any]] | list[str] | None,
        "Per kind: bytes 'addr' or {addr, size}; integer 'addr', 'addr:u32' or {addr, ty}; "
        "string/global 'addr'; struct 'addr' or {addr, struct}; patch_diff: omit",
    ] = None,
) -> dict[str, Any]:
    """Read static IDB data at addresses or symbols.
    WHEN: you need bytes, an integer, string, typed global, or struct field values at a known address (live process memory: debug_memory).
    RETURNS {data: [row per query]}: bytes {addr, size, hex}; integer {addr, ty, value}; string {addr, value}; global {query, addr, name, value}; struct {addr, struct, members[{name, offset, type, value}]}; patch_diff [{addr, size, original_hex, patched_hex, function?}]; failed rows carry error.
    LIMITS: addresses accept hex, names, name+0x10, segment:addr; bytes size and integer ty default to the item size at addr (bytes max 65536); struct uses the applied type unless struct is given.
    NEXT: decompile for code context; search(kind="bytes") for other occurrences."""

    mapping = {
        "bytes": ("get_bytes", "regions"),
        "integer": ("get_int", "queries"),
        "string": ("get_string", "addrs"),
        "global": ("get_global_value", "queries"),
        "struct": ("read_struct", "queries"),
    }
    normalized_kind = str(kind).lower()
    if normalized_kind == "patch_diff":
        from . import api_memory

        return ToolEnvelope(api_memory.patched_ranges()).to_dict()
    if normalized_kind not in mapping:
        _unsupported("memory read kind", kind, get_args(MemoryReadKind))
    name, argument_name = mapping[normalized_kind]
    normalized = _normalize_memory_queries(normalized_kind, list(queries or []))
    rows = _legacy_call(name, {argument_name: normalized})
    return ToolEnvelope([_compact_memory_row(normalized_kind, row) for row in rows]).to_dict()


@tool
def disassemble(
    addr: Annotated[str, "Function name or hexadecimal address"],
    max_instructions: Annotated[int, "Maximum instructions"] = 500,
    offset: Annotated[int, "Instruction offset"] = 0,
    include_total: Annotated[bool, "Include total instruction count"] = False,
) -> dict[str, Any]:
    """WHEN you need exact instructions (decompiler failure, crypto, shellcode, or verifying pseudocode); for an overview use analysis_run(function).
    RETURNS {data{addr, asm{name, start_ea, lines, stack_frame?, return_type?, arguments?}, instruction_count, total_instructions, cursor{next}|{done}}} with `addr  text` lines.
    LIMITS max_instructions per call (max 50000); offset pages within one function, or walks linearly from addr when it is not in a function; total_instructions only with include_total. NEXT disassemble(offset=cursor.next) or graph_query(cfg) for blocks."""
    result = _legacy_call("disasm", {"addr": addr, "max_instructions": max_instructions, "offset": offset, "include_total": include_total})
    return ToolEnvelope(result).to_dict()


@tool
def signature_create(
    addrs: Annotated[list[str], "Functions or addresses to sign"],
    format: Annotated[SignatureFormat, "ida, x64dbg, mask, or bitmask"] = "ida",
    wildcard_operands: Annotated[bool, "Wildcard relocatable operands"] = True,
    max_length: Annotated[int, "Maximum signature length in bytes before giving up"] = 1000,
    anchor: Annotated[
        Literal["function", "address"],
        "function: sign each containing function's start; address: sign the exact address (mid-function OK)",
    ] = "function",
) -> dict[str, Any]:
    """WHEN matching this function or instruction in another build, use this; for callers/callees use graph_query.
    RETURNS {data[{query, addr, name?, signature, format, unique, error?}]}; name only for anchor=function.
    LIMITS shortest unique pattern from the anchor; errors when none fits in max_length bytes; anchor=function rejects addresses outside functions. NEXT search(bytes) to find matches."""
    normalized_format = str(format).lower()
    if normalized_format not in get_args(SignatureFormat):
        _unsupported("signature format", format, get_args(SignatureFormat))
    if anchor not in ("function", "address"):
        _unsupported("signature anchor", anchor, ("function", "address"))
    tool_name = "make_signature_for_function" if anchor == "function" else "make_signature"
    result = _legacy_call(tool_name, {"addrs": addrs, "format": normalized_format, "wildcard_operands": wildcard_operands, "max_length": max_length})
    return ToolEnvelope(result).to_dict()


@idasync
def _similar_functions(target: str, limit: int, min_score: float) -> Any:
    from . import api_recovery
    from .utils import parse_address

    return api_recovery.similar_functions(parse_address(target), limit, min_score)


_BATCH_SECTIONS = {
    "decompile": "include_decompile",
    "disasm": "include_disasm",
    "callers": "include_callers",
    "callees": "include_callees",
    "strings": "include_strings",
    "constants": "include_constants",
    "blocks": "include_basic_blocks",
}
_DEFAULT_BATCH_SECTIONS = ("decompile", "callees", "strings")
_DEFAULT_EXCERPT_LINES = 120


def _batch_queries(targets: list[str], options: dict[str, Any]) -> list[dict[str, Any]]:
    sections = [str(section).lower() for section in options.get("sections") or _DEFAULT_BATCH_SECTIONS]
    for section in sections:
        if section not in _BATCH_SECTIONS:
            _unsupported("batch section", section, tuple(_BATCH_SECTIONS))
    flags = {flag: name in sections for name, flag in _BATCH_SECTIONS.items()}
    return [
        {
            "query": target,
            **flags,
            "include_xrefs": False,
            "include_declarations": bool(options.get("include_declarations", False)),
            "max_decompile_lines": max(1, int(options.get("max_lines") or _DEFAULT_EXCERPT_LINES)),
            "max_callers": 50,
            "max_callees": 50,
            "max_strings": 50,
            "max_constants": 50,
            "max_blocks": 100,
        }
        for target in targets
    ]


def _analysis_sync(mode: str, targets: list[str], options: dict[str, Any]) -> Any:
    if mode == "triage":
        return _legacy_call("survey_binary", {"detail_level": options.get("detail_level", "fast")})
    if mode == "function":
        if len(targets) != 1:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Function analysis requires one target")
        return _legacy_call(
            "analyze_function",
            {
                "addr": targets[0],
                "include_asm": bool(options.get("include_asm", False)),
                "include_declarations": bool(options.get("include_declarations", False)),
                "include_comments": bool(options.get("include_comments", False)),
                "max_lines": max(1, int(options.get("max_lines") or _DEFAULT_EXCERPT_LINES)),
            },
        )
    if mode == "component":
        return _legacy_call("analyze_component", {"addrs": targets})
    if mode == "batch":
        return _legacy_call("analyze_batch", {"queries": _batch_queries(targets, options)})
    if mode == "similar":
        if len(targets) != 1:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Similar analysis requires one target")
        return _similar_functions(
            targets[0],
            int(options.get("limit", 20) or 20),
            float(options.get("min_score", 0.3) or 0.3),
        )
    if mode == "emulate":
        if len(targets) != 1:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Emulate analysis requires one target")
        from .emulate import emulate

        return emulate(targets[0], options)
    _unsupported("analysis mode", mode, get_args(AnalysisMode))


@tool
def analysis_run(
    mode: Annotated[AnalysisMode, "triage, function, component, batch, similar, deep, or emulate"],
    targets: Annotated[list[str] | None, "Seed functions or addresses"] = None,
    options: Annotated[AnalysisOptions | None, "Analysis budgets and mode options"] = None,
) -> dict[str, Any]:
    """WHEN choosing analysis depth; for exact instructions use disassemble, for full pseudocode use decompile.
    RETURNS {data}; deep returns a job record. Modes:
    triage (no targets): binary overview.
    function (1 target): prototype, decompile excerpt, next_line_offset, strings, constants, callers/callees, xrefs, basic_blocks.
    component (N): summaries, internal call graph, shared globals.
    batch (N): options.sections per function.
    similar (1): mnemonic 3-gram matches {addr, name, score, strings}.
    emulate (1): Unicorn run per options.calls entry -> {status, return, writes, warnings}; only malloc/calloc/memcpy/memmove/memset/strlen are modelled.
    deep (N): cancellable job, function analysis plus dataflow per target.
    LIMITS one mode per call; lists capped at 50. NEXT decompile(line_offset=next_line_offset) for more pseudocode; job_status/job_result for deep."""
    normalized = str(mode).lower()
    effective_options = dict(options or {})
    if normalized not in get_args(AnalysisMode):
        _unsupported("analysis mode", mode, get_args(AnalysisMode))
    effective_targets = list(targets or [])
    if normalized != "deep":
        return ToolEnvelope(_analysis_sync(normalized, effective_targets, effective_options)).to_dict()
    skip_triage = bool(effective_options.get("skip_triage", True)) and bool(effective_targets)

    def run(context: JobContext) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if not skip_triage:
            context.progress(0.05, "triage")
            result["triage"] = _analysis_sync("triage", [], effective_options)
        functions: list[dict[str, Any]] = []
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
        result["functions"] = functions
        return result

    return _jobs().submit("analysis.deep", run, database=_database_id()).to_dict(include_result=False)


@idasync
def _graph_pages(
    kind: str,
    pending: list[tuple[int, str, dict[str, Any]]],
    max_depth: int,
    limit: int,
    options: dict[str, Any],
) -> list[dict[str, Any]]:
    """calls/callers/field_xrefs page per pending target on the IDA main thread; failures become {query, error} rows."""
    from .api_analysis import _field_xrefs, _split_field_target, call_graph

    pages: list[dict[str, Any]] = []
    for _index, target, state in pending:
        try:
            if kind == "field_xrefs":
                page = _field_xrefs(*_split_field_target(target), state["offset"], limit)
            else:
                page = call_graph(
                    target,
                    "callees" if kind == "calls" else "callers",
                    max_depth,
                    limit,
                    state["offset"],
                    options["max_edges_per_func"],
                    options["include_indirect"],
                )
        except (McpToolError, ValueError) as exc:  # bad target; cancellation/timeouts propagate
            page = {"query": target, "error": str(exc)}
        pages.append(page)
    return pages


@tool
def graph_query(
    kind: Annotated[GraphKind, "xrefs, xrefs_from, xrefs_both, calls, callers, path, field_xrefs, cfg, or callsite_args"],
    targets: Annotated[list[str], "Functions/addresses (path: [from, to]; field_xrefs: 'Struct.field')"],
    max_depth: Annotated[int, "calls/callers/path: maximum call hops (0-20)"] = 3,
    limit: Annotated[int, "Maximum rows per target page (nodes, xrefs, blocks, or calls)"] = 1000,
    cursor: Annotated[str | None, "Opaque continuation cursor"] = None,
    options: Annotated[GraphOptions | None, "xref_type, include_indirect, max_edges_per_func, max_paths"] = None,
) -> dict[str, Any]:
    """WHEN code relationships matter: who calls whom, who references an address or struct field, how A reaches B.
    RETURNS {data, next_cursor, warnings?}, rows per target:
    xrefs/xrefs_from/xrefs_both: {query, data[{addr, from, to, type, fn}], next_offset, total}.
    calls/callers: {root, nodes[{addr, name, depth, indirect_calls?, address_taken?}], edges[{from, to, site, type}], per_func_capped?}.
    path [from, to]: {paths[[{addr, name, site?}]], length}.
    field_xrefs 'Struct.field': {offset, xrefs[{addr, type, fn, text?}]}.
    cfg: basic blocks. callsite_args: calls to the target with decoded args.
    LIMITS limit caps each target page; resume with next_cursor (same kind/targets); path is not paged; max_depth applies to calls/callers/path; failing targets yield {query, error}. NEXT decompile a node or site; dataflow_trace for value flow."""
    normalized = str(kind).lower()
    opts = dict(options or {})
    xref_type = str(opts.get("xref_type") or "any").lower()
    if xref_type not in {"any", "code", "data"}:
        _unsupported("xref_type", xref_type, ("any", "code", "data"))
    graph_options = {
        "include_indirect": bool(opts.get("include_indirect", True)),
        "max_edges_per_func": max(1, min(int(opts.get("max_edges_per_func") or 100), 5000)),
        "max_paths": max(1, min(int(opts.get("max_paths") or 10), 1000)),
    }
    depth = max(0, min(int(max_depth), 20))
    warnings: list[str] = []

    if normalized in {"xrefs", "xrefs_from", "xrefs_both", "cfg", "callsite_args", "calls", "callers", "field_xrefs"}:
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
        elif normalized == "callsite_args":
            from .hexrays_ctree import callsite_args

            result = [callsite_args(target, state["offset"], limit) for _index, target, state in pending]
        elif normalized in {"calls", "callers"}:
            result = _graph_pages(normalized, pending, depth, max(1, min(int(limit), 100000)), graph_options)
        elif normalized == "field_xrefs":
            result = _graph_pages(normalized, pending, depth, max(1, min(int(limit), 1000)), graph_options)
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
                            "xref_type": xref_type,
                            "offset": state["offset"],
                            "count": limit,
                        }
                        for _index, target, state in pending
                    ]
                },
            )
        next_cursor = _per_target_next_cursor(result, pending, len(targets), "graph")
    elif normalized == "path":
        if len(targets) != 2:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"kind=path takes exactly 2 targets [from, to], got {len(targets)}")
        if cursor:
            raise VNextError(ErrorCode.INVALID_OPERATION, "kind=path results are not paged; omit cursor")
        from .api_analysis import call_paths

        result = idasync(call_paths)(
            targets[0],
            targets[1],
            max(1, depth),
            graph_options["max_paths"],
            graph_options["max_edges_per_func"],
            graph_options["include_indirect"],
        )
        next_cursor = None
    else:
        _unsupported("graph kind", kind, get_args(GraphKind))
    if max_depth != 3 and normalized not in {"calls", "callers", "path"}:
        warnings.append(f"max_depth is ignored for kind={normalized}")
    return ToolEnvelope(
        result,
        warnings=warnings,
        truncated=next_cursor is not None or _result_truncated(result),
        next_cursor=next_cursor,
    ).to_dict()


@tool
def dataflow_trace(
    addr: Annotated[str, "Seed: address, function name, or 'func:var' (local variable or argument)"],
    direction: Annotated[DataflowDirection, "forward (where the value goes), backward (where it comes from), or both"] = "forward",
    max_depth: Annotated[int, "Maximum def-use hops from the seed"] = 3,
    variable: Annotated[str | None, "Local variable or argument name in the function containing addr"] = None,
    options: Annotated[DataflowOptions | None, "Output options"] = None,
) -> dict[str, Any]:
    """WHEN asking where a value inside one function flows to (or comes from); for source->sink questions across calls use taint_analyze.
    RETURNS {engine, fidelity, nodes[{id, address, line, defines, uses, microcode?}], edges[{source, target, variable, kind:must|may}], unsupported_edges, warnings, truncated}; line is the pseudocode statement, defines/uses are variable names.
    LIMITS one function; values passed to calls are not followed into callees; memory through pointers is one location. Unknown variables error with the variable list. Without Hex-Rays, or for data addresses, engine=reference_flow (xref hops, not data flow). NEXT taint_analyze across calls; decompile for context."""
    normalized = str(direction).lower()
    if normalized not in get_args(DataflowDirection):
        _unsupported("data-flow direction", direction, get_args(DataflowDirection))
    include_microcode = bool((options or {}).get("include_microcode", False))
    try:
        from .hexrays_dataflow import trace_function

        return trace_function(
            addr,
            variable=variable,
            direction=normalized,
            max_depth=max_depth,
            include_microcode=include_microcode,
        )
    except VNextError as exc:
        if exc.code is not ErrorCode.NOT_SUPPORTED or variable is not None:
            raise
        fallback_warning = f"Semantic data flow unavailable: {exc}"

    result = _legacy_call("trace_data_flow", {"addr": addr, "direction": normalized, "max_depth": max_depth})
    nodes, edges, truncated = normalize_reference_flow_graph(result if isinstance(result, dict) else {})
    warnings = [fallback_warning, "Result is reference flow (xref hops), not semantic data flow"]
    if isinstance(result, dict) and result.get("error"):
        warnings.append(str(result["error"]))
    graph = AnalysisGraph(
        engine=AnalysisEngine.REFERENCE_FLOW,
        fidelity="reference",
        nodes=nodes,
        edges=edges,
        unsupported_edges=[
            {"kind": "semantic_def_use", "reason": "no decompiled data flow for this seed"},
            {"kind": "memory_alias", "reason": "reference flow does not model aliases"},
        ],
        warnings=warnings,
        truncated=truncated,
    )
    return graph.to_dict()


@tool
def taint_analyze(
    sources: Annotated[list[str], "Sources: addresses, 'func:var', function names (their parameters), or API/import names (their results and written buffers at every call site)"],
    sinks: Annotated[list[str], "Sinks: function/import names (a call receiving the value as any argument) or statement addresses"],
    max_depth: Annotated[int, "Maximum function hops into direct callees (0 = stay in the source function)"] = 2,
    sanitizers: Annotated[list[str] | None, "Functions or addresses that stop propagation when the value reaches them"] = None,
    options: Annotated[TaintOptions | None, "Propagation domains and result budgets"] = None,
) -> dict[str, Any]:
    """WHEN asking whether data from a source can reach a sink (argv -> printf, recv -> memcpy).
    RETURNS {engine, fidelity, hits[{source, sink, steps[{func, address, line}], hops, domains, confidence}], sanitizer_annotations, functions_analyzed, unsupported_edges, warnings, truncated}; steps are pseudocode statements from source to sink.
    LIMITS needs Hex-Rays; follows def-use edges and direct calls into user functions (by parameter position) up to max_depth hops and 20 functions; no flow back through return values or indirect calls. A call result and pointer arguments are tainted when any argument is. confidence is a heuristic, not a proof. Unknown symbols error with suggestions. NEXT decompile the step functions to confirm; investigation_add_finding to record."""
    from .hexrays_dataflow import taint

    effective_options = dict(options or {})
    all_domains = get_args(TaintDomain)
    domains = set(effective_options.get("domains") or all_domains)
    for domain in domains:
        if domain not in all_domains:
            _unsupported("taint domain", domain, all_domains)
    max_paths = max(1, min(int(effective_options.get("max_paths", 100)), 1000))
    hops = max(0, int(max_depth))
    result = taint(list(sources), list(sinks), list(sanitizers or []), max_hops=hops, max_paths=max_paths, domains=domains)
    return {
        "engine": AnalysisEngine.HEXRAYS_MICROCODE.value,
        "fidelity": "semantic_interprocedural" if hops else "semantic_intraprocedural",
        "hits": result["hits"],
        "sanitizer_annotations": result["sanitizer_annotations"],
        "functions_analyzed": result["functions_analyzed"],
        "truncated": result["truncated"],
        "unsupported_edges": [
            {"kind": "callee_effects", "reason": "callee results and pointer writes are approximated at the call site"},
            {"kind": "indirect_call", "reason": "indirect call targets are not followed"},
            {"kind": "memory_alias", "reason": "stores and loads through pointers are joined conservatively"},
            {"kind": "thread_handoff", "reason": "concurrent taint propagation is not modeled"},
        ],
        "warnings": result["warnings"],
    }


@tool
def job_status(
    job_id: Annotated[str, "Job identifier"],
    wait_sec: Annotated[float, "Block up to this many seconds (max 30) until the job ends"] = 0,
) -> dict[str, Any]:
    """WHEN a background job (analysis_run deep, investigation_start) is running; pass wait_sec instead of polling in a loop.
    RETURNS {job_id, kind, state, progress, message, error} (error set when failed); no result payload.
    LIMITS state is queued/running/completed/failed/cancelled/interrupted; wait_sec returns early once the state is terminal; jobs from a previous worker restore as interrupted. NEXT job_result once state=completed."""
    import time

    deadline = time.monotonic() + max(0.0, min(float(wait_sec or 0), 30.0))
    while True:
        status = _jobs().status(job_id, include_result=False)
        if status["state"] not in ("queued", "running") or time.monotonic() >= deadline:
            return status
        from .sync import run_main_thread_work

        run_main_thread_work()  # idalib: this request occupies the main loop the job needs
        time.sleep(0.02)


@tool
def job_cancel(job_id: Annotated[str, "Job identifier"]) -> dict[str, Any]:
    """WHEN a background job is no longer needed, use this instead of waiting.
    RETURNS {job_id, cancel_requested}.
    LIMITS cooperative: running jobs stop at their next checkpoint. NEXT job_status to confirm state=cancelled."""
    return {"job_id": job_id, "cancel_requested": _jobs().cancel(job_id)}


@tool
def job_result(
    job_id: Annotated[str, "Completed job identifier"],
    cursor: Annotated[str | None, "Opaque result cursor"] = None,
    limit: Annotated[int, "Maximum list items"] = 100,
) -> dict[str, Any]:
    """WHEN job_status reports state=completed, use this to fetch the payload; poll job_status first.
    RETURNS {data, next_cursor?} envelope; list results paginate by cursor/limit.
    LIMITS raises JOB_INTERRUPTED with the current state while the job is not completed; list pages cap at 1000 items. NEXT investigation_add_finding to record conclusions."""
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
    LIMITS triage (unless budgets.skip_triage) plus one function analysis per seed, at most budgets.max_seeds (default 20); findings arrive via investigation_add_finding. NEXT job_status(wait_sec=...) then investigation_get."""
    effective_seeds = list(seeds or [])
    effective_budgets = dict(budgets or {})
    max_seeds = max(1, min(int(effective_budgets.get("max_seeds") or 20), 100))
    effective_seeds, skipped_seeds = effective_seeds[:max_seeds], effective_seeds[max_seeds:]
    manager = _investigations()
    record = manager.create(objective, database=_database_id(), seeds=effective_seeds)
    if skipped_seeds:
        manager.set_state(record.investigation_id, record.state, skipped_seeds=skipped_seeds)
    def run(context: JobContext) -> dict[str, Any]:
        try:
            triage = None
            if not effective_budgets.get("skip_triage"):
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
    evidence: Annotated[
        list[dict[str, Any]] | None,
        "Evidence items: {addr|address|ea, description|text|data|note, source?, confidence?}; each needs an address or a description",
    ] = None,
    tags: Annotated[list[str] | None, "Finding tags"] = None,
    apply_to_idb: Annotated[bool, "Also bookmark every evidence address as '[severity] title' (undoable commit)"] = False,
) -> dict[str, Any]:
    """WHEN a conclusion has tool evidence, use this; bare notes do not belong here.
    RETURNS the finding record (evidence addresses canonical hex); with apply_to_idb also transaction_id of the bookmark commit, or apply_error.
    LIMITS severity is info/low/medium/high/critical; confidence clamps to 0-1; evidence items without address and description raise INVALID_OPERATION; apply_to_idb needs annotate scope and resolvable addresses. NEXT investigation_export for the report; mutation_rollback(transaction_id) removes the bookmarks."""
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
        resolve_address=_resolve_address_text,
    )
    result = finding.to_dict()
    if not apply_to_idb:
        return result
    addresses = list(dict.fromkeys(item.address for item in finding.evidence if item.address))
    if not addresses:
        result["apply_error"] = {"code": ErrorCode.INVALID_OPERATION.value, "message": "No evidence address to bookmark"}
        return result
    label = f"[{finding.severity}] {finding.title}"
    try:
        committed = mutation_preview(
            [{"kind": "bookmark", "addr": addr, "name": label, "prefix": ""} for addr in addresses],
            commit=True,
        )
    except VNextError as exc:
        result["apply_error"] = exc.to_dict()
        return result
    result["transaction_id"] = committed["transaction_id"]
    return result


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
    "set_operand_type": ("set_op_type", "items", SafetyScope.ANNOTATE),
    "make_data": ("make_data", "items", SafetyScope.MODIFY),
    "declare_stack": ("declare_stack", "items", SafetyScope.ANNOTATE),
    "delete_stack": ("delete_stack", "items", SafetyScope.ANNOTATE),
    "upsert_enum": ("enum_upsert", "queries", SafetyScope.ANNOTATE),
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
    "enum_upsert": "upsert_enum",
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


@idasync
def _resolve_address_text(text: str) -> str:
    """Resolve a symbol/address expression to canonical hex on the IDA main thread."""
    from .utils import parse_address

    return hex(parse_address(text))


def _parse_mutation_address(raw: Any, *, index: int, field: str = "addr") -> str:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raise VNextError(
            ErrorCode.INVALID_OPERATION,
            f"Mutation operation {index} has an empty address",
        )
    if isinstance(raw, int) and not isinstance(raw, bool):
        return hex(raw)
    text = str(raw).strip()
    try:
        return hex(int(text, 0))
    except ValueError:
        pass
    try:
        return _resolve_address_text(text)
    except Exception as exc:
        raise VNextError(
            ErrorCode.INVALID_OPERATION,
            f"Mutation operation {index} failed to resolve {field}: {exc}",
        ) from exc


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
        if args.get("old_name") and args.get("new_name"):
            item = {"old": str(args["old_name"]), "new": str(args["new_name"])}
            group = "data"
            if args.get("func_addr"):
                item["func_addr"] = _parse_mutation_address(args["func_addr"], index=index, field="func_addr")
                group = "local"
            reshaped = {group: [item]}
            _copy_passthrough(args, reshaped, _RENAME_PASSTHROUGH_KEYS)
            return canonical, reshaped
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
        edits = _as_dict_list(args.pop("edits", args.pop("items", None)))
        if edits is not None:
            for edit in edits:
                if "addr" in edit:
                    edit["addr"] = _parse_mutation_address(edit["addr"], index=index)
            return canonical, {**args, "edits": edits}
        type_text = next((args[key] for key in _TYPE_TEXT_KEYS if args.get(key)), None)
        if (args.get("addr") or args.get("name")) and type_text:
            edit = {"type": str(type_text)}
            if args.get("addr"):
                edit["addr"] = _parse_mutation_address(args["addr"], index=index)
            _copy_passthrough(args, edit, ("kind", "name", "variable"))
            return canonical, {"edits": [edit]}

    elif canonical == "declare_type" and not args.get("decls") and args.get("decl"):
        return canonical, {"decls": args["decl"]}

    elif canonical == "upsert_enum" and "queries" not in args and args.get("name"):
        query = {"name": str(args["name"]), "members": args.get("members") or []}
        _copy_passthrough(args, query, ("bitfield",))
        return canonical, {"queries": [query]}

    elif canonical == "declare_stack" and "items" not in args and "ty" not in args and args.get("type"):
        args["ty"] = args.pop("type")

    elif canonical == "set_operand_type" and "items" not in args and "operand_kind" in args:
        args["kind"] = args.pop("operand_kind")

    target = _OPERATION_TARGETS.get(canonical)
    if target is not None and canonical not in {"rename", "comment", "append_comment", "set_type"}:
        _canonicalize_item_addresses(target[1], args, index=index)
    return canonical, args


_TYPE_TEXT_KEYS = ("type", "ty", "decl", "signature")
_ITEM_ADDRESS_KEYS = ("addr", "func_addr", "target_addr", "end")


def _payload_items(argument_name: str, arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Item dicts the legacy tool will receive (mirrors _apply_operation)."""
    if argument_name == "item":
        return [arguments]
    if argument_name == "path":
        return []
    return _as_dict_list(arguments.get(argument_name, arguments.get("items", arguments))) or []


def _canonicalize_item_addresses(argument_name: str, arguments: dict[str, Any], *, index: int) -> None:
    for item in _payload_items(argument_name, arguments):
        for key in _ITEM_ADDRESS_KEYS:
            if item.get(key) not in (None, ""):
                item[key] = _parse_mutation_address(item[key], index=index, field=key)


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
    if kind == "save_database":
        return False
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


def _hex_ea(raw: Any) -> int | None:
    """Parse an address already canonicalized by _parse_operations."""
    if raw in (None, ""):
        return None
    try:
        return int(str(raw), 0)
    except ValueError:
        return None


def _decl_text(decl: str) -> str:
    text = decl.strip()
    return text if text.endswith(";") else text + ";"


def _declared_type_names(decl: str) -> list[str]:
    """Names a C declaration string defines (first parsed type plus tagged/typedef names)."""
    import re

    import ida_typeinf

    names: list[str] = []
    try:
        parsed = ida_typeinf.parse_decl(ida_typeinf.tinfo_t(), None, _decl_text(decl), ida_typeinf.PT_SIL | ida_typeinf.PT_TYP)
        if parsed:
            names.append(parsed)
    except Exception:
        pass
    names += re.findall(r"\b(?:struct|union|enum|class)\s+([A-Za-z_]\w*)\s*(?::[^{;]*)?\{", decl)
    names += re.findall(r"\btypedef\b[^;]*?\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*;", decl)
    return list(dict.fromkeys(names))


def _local_type_decl(name: str) -> str | None:
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name):
        return None
    try:
        return tif._print(name, ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_DEF)
    except Exception:
        return str(tif)


def _frame_member_type(func_ea: int, name: str) -> str | None:
    import ida_frame
    import ida_funcs
    import ida_typeinf

    func = ida_funcs.get_func(func_ea)
    frame = ida_typeinf.tinfo_t()
    if func is None or not ida_frame.get_func_frame(frame, func):
        return None
    _index, udm = frame.get_udm(name)
    return str(udm.type) if udm else None


def _user_lvar_type(func_ea: int, name: str) -> str | None:
    import ida_funcs
    import ida_hexrays

    func = ida_funcs.get_func(func_ea)
    lvinf = ida_hexrays.lvar_uservec_t()
    if func is None or not ida_hexrays.restore_user_lvar_settings(lvinf, func.start_ea):
        return None
    for saved in lvinf.lvvec:
        if saved.name == name:
            return str(saved.type)
    return None


def _decl_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value or [] if str(item).strip()]


@idasync
def _mutation_before_state(operation: MutationOperation) -> Any:
    """Capture the IDB state an operation targets; re-read to revalidate a stale preview."""

    try:
        import ida_bytes
        import ida_funcs
        import ida_lines
        import ida_name
        import ida_ua
        import idaapi
        import idc
    except Exception:
        return None

    kind = operation.kind
    arguments = operation.arguments
    items = _payload_items(_OPERATION_TARGETS[kind][1], arguments)
    try:
        if kind == "rename":
            before: dict[str, list[dict[str, Any]]] = {}
            for group in _RENAME_BATCH_KEYS:
                names = []
                for item in _as_dict_list(arguments.get(group)) or []:
                    ea = _hex_ea(item.get("addr") or item.get("func_addr"))
                    if ea is not None:
                        names.append({"addr": hex(ea), "name": ida_name.get_name(ea) or ""})
                    elif item.get("old"):
                        found = idaapi.get_name_ea(idaapi.BADADDR, str(item["old"]))
                        names.append({"old": str(item["old"]), "addr": None if found == idaapi.BADADDR else hex(found)})
                if names:
                    before[group] = names
            return before or None
        if kind == "declare_type":
            return [
                {"name": name, "decl": _local_type_decl(name)}
                for decl in _decl_list(arguments.get("decls"))
                for name in _declared_type_names(decl)
            ]
        if kind == "upsert_enum":
            enums = []
            for query in items:
                enum_id = idc.get_enum(str(query.get("name", "")))
                members = {}
                for member in _as_dict_list(query.get("members")) or []:
                    member_id = idc.get_enum_member_by_name(str(member.get("name", "")))
                    members[str(member.get("name", ""))] = (
                        None if member_id == idc.BADADDR else idc.get_enum_member_value(member_id)
                    )
                enums.append({"name": query.get("name"), "exists": enum_id != idc.BADADDR, "members": members})
            return enums
        if kind in {"apply_flirt", "load_til", "save_database"}:
            return None
        states = []
        for item in items:
            ea = _hex_ea(item.get("addr"))
            if kind == "set_type" and ea is None and item.get("name"):
                found = idaapi.get_name_ea(idaapi.BADADDR, str(item["name"]))
                ea = None if found == idaapi.BADADDR else found
            if ea is None:
                return None
            state: dict[str, Any] = {"addr": hex(ea)}
            if kind in {"comment", "append_comment"}:
                state["comment"] = idaapi.get_cmt(ea, False) or ""
                func = ida_funcs.get_func(ea)
                state["func_comment"] = (ida_funcs.get_func_cmt(func, False) or "") if func else None
            elif kind == "bookmark":
                from .api_modify import MAX_BOOKMARK_SLOTS

                state["bookmark"] = next(
                    (idc.get_bookmark_desc(slot) for slot in range(MAX_BOOKMARK_SLOTS) if idc.get_bookmark(slot) == ea),
                    None,
                )
            elif kind in {"patch_bytes", "patch_asm", "write_integer"}:
                size = item.get("size")
                if not size and isinstance(item.get("data"), str):
                    size = len(item["data"].replace(" ", "")) // 2
                size = max(1, min(int(size or 16), 64))
                raw = ida_bytes.get_bytes(ea, size)
                state["bytes"] = raw.hex() if raw else None
            elif kind == "set_type":
                state["type"] = idc.get_type(ea)
                if item.get("variable"):
                    state["lvar_type"] = _user_lvar_type(ea, str(item["variable"]))
                elif item.get("name") and item.get("addr"):
                    state["frame_type"] = _frame_member_type(ea, str(item["name"]))
            elif kind in {"declare_stack", "delete_stack"}:
                state["name"] = str(item.get("name", ""))
                state["type"] = _frame_member_type(ea, state["name"])
            elif kind == "set_operand_type":
                op_n = int(item.get("op_n", 0))
                state["op_n"] = op_n
                state["operand"] = ida_lines.tag_remove(ida_ua.print_operand(ea, op_n) or "")
            else:  # define_function, define_code, undefine, make_data
                func = ida_funcs.get_func(ea)
                state.update(
                    head=hex(ida_bytes.get_item_head(ea)),
                    flags=ida_bytes.get_flags(ea) & (ida_bytes.MS_CLS | ida_bytes.DT_TYPE),
                    size=ida_bytes.get_item_size(ea),
                    func=hex(func.start_ea) if func else None,
                    type=idc.get_type(ea),
                )
            states.append(state)
        return states or None
    except Exception:
        return None


_UNCHECKED_KINDS = frozenset({"patch_asm", "apply_flirt", "load_til", "save_database"})
_OPERAND_KINDS = ("stroff", "offset", "stkvar", "hex", "dec", "char", "binary", "octal", "enum")


def _validate_operation(index: int, operation: MutationOperation, pending: set[str]) -> bool:
    """Raise INVALID_OPERATION for unresolvable targets or unparsable types.

    Returns False when content was not checked (assembly, FLIRT, TIL) or depends on
    a type declared earlier in the same transaction. Must run on the main thread.
    """
    import re

    import ida_bytes
    import ida_typeinf
    import idc

    from .api_types import _parse_tinfo
    from .utils import get_type_by_name

    kind = operation.kind
    items = _payload_items(_OPERATION_TARGETS[kind][1], operation.arguments)
    deferred = False

    def invalid(message: str) -> NoReturn:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"Mutation operation {index} {kind}: {message}")

    def check_type(text: str, parse: Callable[[str], Any]) -> None:
        nonlocal deferred
        try:
            parse(text)
        except Exception as exc:
            if any(re.search(rf"\b{re.escape(name)}\b", text) for name in pending):
                deferred = True  # declared by an earlier operation of this transaction
            else:
                invalid(str(exc))

    if kind not in {"rename", "declare_type", "upsert_enum", "apply_flirt", "load_til", "save_database"}:
        for item in items:
            for key in ("addr", "func_addr", "target_addr"):
                ea = _hex_ea(item.get(key))
                if ea is not None and not ida_bytes.is_mapped(ea):
                    invalid(f"{key} {hex(ea)} is not a mapped address")

    if kind == "set_type":
        for edit in items:
            text = next((str(edit[key]) for key in ("ty", "type", "decl", "declaration", "signature") if edit.get(key)), "")
            if not text:
                invalid("missing type")
            is_func = str(edit.get("kind", "")).lower() == "function" or bool(edit.get("signature"))
            check_type(text, lambda value: _parse_tinfo(value, func=is_func))
    elif kind == "make_data":
        for item in items:
            check_type(str(item.get("type") or ""), _parse_tinfo)
    elif kind == "declare_stack":
        for item in items:
            check_type(str(item.get("ty") or ""), get_type_by_name)
    elif kind == "declare_type":
        for decl in _decl_list(operation.arguments.get("decls")):

            def parse_decl(text: str) -> None:
                if ida_typeinf.parse_decl(ida_typeinf.tinfo_t(), None, _decl_text(text), ida_typeinf.PT_SIL | ida_typeinf.PT_TYP) is None:
                    raise ValueError(f"declaration does not parse: {text}")

            check_type(decl, parse_decl)
            pending.update(_declared_type_names(decl))
    elif kind == "upsert_enum":
        pending.update(str(query.get("name")) for query in items if query.get("name"))
    elif kind == "set_operand_type":
        for item in items:
            display = str(item.get("kind", "")).strip().lower()
            if display not in _OPERAND_KINDS:
                invalid(f"operand_kind must be one of {', '.join(_OPERAND_KINDS)}")
            named = str(item.get("enum" if display == "enum" else "struct", "")).strip()
            if display in {"enum", "stroff"}:
                if not named:
                    invalid(f"{display} requires {'enum' if display == 'enum' else 'struct'}")
                exists = idc.get_enum(named) != idc.BADADDR if display == "enum" else _local_type_decl(named) is not None
                if not exists and named not in pending:
                    invalid(f"unknown {display} type {named}")
                deferred = deferred or not exists
    return not deferred and kind not in _UNCHECKED_KINDS


@idasync
def _preview_states(operations: list[MutationOperation]) -> list[dict[str, Any]]:
    """Validate and snapshot every operation in one main-thread hop."""
    pending: set[str] = set()
    states = []
    for index, operation in enumerate(operations):
        state: dict[str, Any] = {"validated": _validate_operation(index, operation, pending)}
        before = _mutation_before_state(operation)
        if before is not None:
            state["before"] = before
        states.append(state)
    return states


def _revalidate_preview(preview: MutationPreview) -> bool:
    """True when every operation's targeted state still matches the preview."""

    if len(preview.changes) != len(preview.operations):
        return False
    for operation, change in zip(preview.operations, preview.changes):
        before = change.get("before") if isinstance(change, dict) else None
        if before is None:
            return False
        if _mutation_before_state(operation) != before:
            return False
    return True


@idasync
def _clear_decompiler_cache() -> None:
    """Drop cached pseudocode so decompile reflects committed types/names."""
    try:
        import ida_hexrays

        if ida_hexrays.init_hexrays_plugin():
            ida_hexrays.clear_cached_cfuncs()
    except Exception:
        pass


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
        list[MutationOp],
        "Operations applied in order; flat fields or nested arguments{}. Per kind: "
        "rename {addr,name} | {old_name,new_name[,func_addr]}; comment/append_comment {addr,comment}; "
        "bookmark {addr,name}; declare_type {decl}; set_type {addr|name,type[,variable]}; "
        "upsert_enum {name,members[{name,value}][,bitfield]}; declare_stack {addr,offset,name,type}; "
        "delete_stack {addr,name}; patch_bytes {addr,data}; write_integer {addr,ty,value}; patch_asm {addr,asm}; "
        "define_function {addr[,end]}; define_code {addr}; undefine {addr[,end|size]}; make_data {addr,type[,name]}; "
        "set_operand_type {addr,op_n,operand_kind[,struct|enum|target_addr]}; apply_flirt/load_til {name}; "
        "save_database {path}. Batch: items[...] or arguments{func:[{addr,name}]}. addr takes hex or symbol names.",
    ],
    commit: Annotated[bool, "Commit immediately; only when every operation is annotate scope"] = False,
) -> dict[str, Any]:
    """WHEN staging any IDB change, use this; commit=true applies annotate-only edits (rename/comment/type/enum/operand display/bookmark/stack) in one call.
    RETURNS {transaction_id, operations[{kind, scope, arguments, validated, before?}], required_scopes, warnings?, receipt? (commit=true)}.
    LIMITS addresses must resolve and types/declarations must parse (INVALID_OPERATION names the operation index); validated=false means content was not checked (asm/FLIRT/TIL or types declared earlier in the batch); previews expire. NEXT mutation_commit(transaction_id), or mutation_rollback after commit=true."""

    parsed = _parse_operations(operations)
    if commit and any(operation.scope is not SafetyScope.ANNOTATE for operation in parsed):
        raise VNextError(
            ErrorCode.INVALID_OPERATION,
            "commit=true is only allowed for annotate-scope operations; call mutation_commit",
        )
    for operation in parsed:
        if operation.kind != "rename":
            continue
        result = _legacy_call("rename", {"batch": {**operation.arguments, "dry_run": True}})
        detail = _legacy_result_failed(result)
        if detail is None and isinstance(result, dict) and result.get("ok") is False:
            detail = result.get("error") or "rename dry-run failed"
        if detail is not None:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"mutation_preview: rename dry-run failed: {detail}")
    states = iter(_preview_states(parsed))
    preview = _TRANSACTIONS.preview(
        _database_id(),
        parsed,
        enabled_scopes=get_active_scopes(),
        preview_operation=lambda _operation: next(states),
    )
    result = preview.to_dict()
    if commit:
        result["receipt"] = _commit_transaction(preview.transaction_id)
        return result
    try:
        from .http import recovery_checkpoints_enabled
    except Exception:
        recovery_checkpoints_enabled = None  # type: ignore[assignment]
    if recovery_checkpoints_enabled is not None and not recovery_checkpoints_enabled():
        warnings = list(result.get("warnings") or [])
        warnings.append("Recovery checkpoints are disabled; mutation_commit will not write a recovery IDB.")
        result["warnings"] = warnings
    return result


def _commit_transaction(transaction_id: str) -> dict[str, Any]:
    try:
        return _TRANSACTIONS.commit(
            transaction_id,
            database=_database_id(),
            enabled_scopes=get_active_scopes(),
            checkpoint=_commit_checkpoint,
            apply_operation=_apply_operation,
            undo=_perform_undo,
            begin=_create_undo_point,
            revalidate=_revalidate_preview,
        ).to_dict()
    finally:
        _clear_decompiler_cache()


@tool
def mutation_commit(transaction_id: Annotated[str, "Preview transaction identifier"]) -> dict[str, Any]:
    """WHEN a staged transaction reviewed clean, use this; for state checks use mutation_status.
    RETURNS the receipt {transaction_id, status, revision_before, revision_after, applied_operations, checkpoint, undo_available, required_scopes, warnings}.
    LIMITS needs every scope the preview listed (byte/code edits need modify); a changed target since preview raises STALE_REVISION; a failing operation undoes the applied ones; recovery checkpoints only when enabled in settings. NEXT mutation_rollback(transaction_id) to undo."""

    return _commit_transaction(transaction_id)


@tool
def mutation_status(transaction_id: Annotated[str, "Transaction identifier"]) -> dict[str, Any]:
    """WHEN following a staged transaction, use this instead of re-previewing.
    RETURNS the preview with status=previewed and expired, or the commit/rollback receipt.
    LIMITS read-only; unknown ids raise TRANSACTION_NOT_FOUND. NEXT mutation_commit/mutation_rollback."""

    return _TRANSACTIONS.status(transaction_id)


@tool
def mutation_rollback(transaction_id: Annotated[str, "Committed transaction identifier"]) -> dict[str, Any]:
    """WHEN undoing the latest commit, use this; older transactions are rejected.
    RETURNS the receipt with status=rolled_back.
    LIMITS latest commit only (any later IDB change raises STALE_REVISION); needs the committed transaction's scopes; uses native undo, else raises REOPEN_REQUIRED with the recovery checkpoint path. NEXT mutation_preview for corrections."""

    try:
        return _TRANSACTIONS.rollback(
            transaction_id,
            rollback_undo=_perform_undo,
            enabled_scopes=get_active_scopes(),
        ).to_dict()
    finally:
        _clear_decompiler_cache()


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
    return ToolEnvelope(_legacy_call(name, target or {})).to_dict()


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
    return ToolEnvelope(_legacy_call(name, {"addr": addr} if normalized == "run_to" else {})).to_dict()


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
    return ToolEnvelope(_legacy_call(name, arguments)).to_dict()


@tool
def debug_state(
    include: Annotated[list[str] | None, "registers, stack, breakpoints, or status"] = None,
    thread: Annotated[int | None, "registers: thread id (default current)"] = None,
    registers: Annotated[list[str] | None, "registers: names to return (default all)"] = None,
) -> dict[str, Any]:
    """WHEN reading stopped state, use this instead of individual dbg_* tools.
    RETURNS {data} envelope keyed by the requested sections.
    LIMITS sections are status/registers/stack/breakpoints (default status+registers+stack); each delegates to one legacy dbg_* read. NEXT debug_control to resume."""
    effective = [str(item).lower() for item in (include if include is not None else ["status", "registers", "stack"])]
    result: dict[str, Any] = {}
    mapping = {"status": "dbg_status", "registers": "dbg_regs", "stack": "dbg_stacktrace", "breakpoints": "dbg_bps"}
    for item in effective:
        if item not in mapping:
            _unsupported("debugger state section", item, ("status", "registers", "stack", "breakpoints"))
        arguments = {"thread": thread, "names": registers} if item == "registers" else {}
        result[item] = _legacy_call(mapping[item], arguments)
    return ToolEnvelope(result).to_dict()


@tool
def debug_memory(action: Annotated[DebugMemoryAction, "read, write, snapshot, or diff"], regions: Annotated[list[dict[str, Any]] | None, "Live memory regions"] = None, confirm_nonrollbackable: Annotated[bool, "Required for writes"] = False, snapshot_id: Annotated[str | None, "Snapshot identifier for diff"] = None) -> dict[str, Any]:
    """WHEN live process bytes matter, use this; for static bytes use memory_read.
    RETURNS {data} envelope; snapshot returns {snapshot_id, regions, value}, diff returns {snapshot_id, changed, before, after}.
    LIMITS writes need confirm_nonrollbackable=true and are non-rollbackable; snapshots are per-database. NEXT debug_state for registers/stack."""
    normalized = str(action).lower()
    effective_regions = list(regions or [])
    if normalized == "read":
        return ToolEnvelope(_legacy_call("dbg_read", {"regions": effective_regions})).to_dict()
    if normalized == "write":
        if not confirm_nonrollbackable:
            raise VNextError(ErrorCode.PROFILE_DENIED, "Live-memory writes require confirm_nonrollbackable=true")
        return ToolEnvelope(_legacy_call("dbg_write", {"regions": effective_regions})).to_dict()
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
        return ToolEnvelope(_legacy_call("py_eval", {"code": code})).to_dict()
    if normalized == "file" and path is not None:
        if SafetyScope.FILESYSTEM not in get_active_scopes():
            raise VNextError(ErrorCode.PROFILE_DENIED, "Python file execution also requires filesystem scope")
        safe_path = get_workspace_policy().resolve(path, must_exist=True)
        return ToolEnvelope(_legacy_call("py_exec_file", {"file_path": str(safe_path)})).to_dict()
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
    database_line = f"Pass database=`{database}` when several databases are open. " if database else ""
    return f"{database_line}Objective: {objective}\n\nWorkflow:\n{workflow}\n\nCite addresses and tool evidence; label uncertainty explicitly."


@prompt
def triage_binary(database: str = "") -> str:
    """Systematic first-pass binary triage."""

    return _prompt("Triage the binary and identify the highest-value analysis targets.", "1. analysis_run(mode=\"triage\") for entrypoints, imports, strings, and ranked functions.\n2. search/entity_query (small limits) to confirm suspicious imports and strings.\n3. analysis_run(mode=\"function\") on the top candidates.\n4. investigation_start to track deeper work.", database)


@prompt
def explain_function(target: str, database: str = "") -> str:
    """Evidence-backed function explanation."""

    return _prompt(f"Explain function {target}.", "analysis_run(mode=\"function\") or decompile (page with line_offset/line_limit; /*0xEA*/ markers give line addresses). graph_query callers and callsite_args for how it is called, memory_read for referenced data. Summarize inputs, outputs, side effects, and confidence.", database)


@prompt
def trace_input_to_sink(source: str, sink: str, database: str = "") -> str:
    """Trace a source toward a security-relevant sink."""

    return _prompt(f"Trace {source} to {sink}.", "graph_query(kind=\"path\") for call-level reachability, callsite_args for the concrete arguments at each hop, then dataflow_trace/taint_analyze. Distinguish microcode def-use from reference-flow fallback and preserve all supporting addresses.", database)


@prompt
def deobfuscate_component(targets: str, database: str = "") -> str:
    """Plan evidence-preserving deobfuscation."""

    return _prompt(f"Analyze obfuscation around {targets}.", "Identify the transformation and document invariants. Annotations (renames, comments, types) may use mutation_preview(commit=true); stage patches with mutation_preview and do not mutation_commit without explicit approval.", database)


@prompt
def review_patch(transaction_id: str, database: str = "") -> str:
    """Review a staged mutation before commit."""

    return _prompt(f"Review mutation transaction {transaction_id}.", "Read mutation_status, verify every before/after change and warning, assess recovery checkpoint requirements, then recommend mutation_commit or rejection.", database)


@prompt
def generate_report(investigation_id: str, format: str = "markdown", database: str = "") -> str:
    """Generate an evidence-backed investigation report."""

    return _prompt(f"Generate a {format} report for investigation {investigation_id}.", "investigation_get to verify findings and evidence, identify unresolved hypotheses, and call investigation_export only after the record is complete.", database)


_install_revision_hook()
_install_debug_hook()
