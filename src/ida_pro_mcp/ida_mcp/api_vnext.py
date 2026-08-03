"""Canonical vNext MCP tools, resources, and prompts.

The canonical layer intentionally delegates proven low-level IDA operations to
the legacy implementations.  This keeps one implementation of IDA behavior
while presenting a smaller and versioned public API.
"""

from __future__ import annotations

import base64
import functools
import json
import os
import platform
import sys
from pathlib import Path
from threading import RLock
from typing import Annotated, Any
from urllib.parse import quote, unquote
from uuid import uuid4

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
from ida_pro_mcp.vnext.jobs import JobContext, JobManager
from ida_pro_mcp.vnext.transactions import RevisionTracker, TransactionManager

from .rpc import (
    MCP_AUDIT,
    MCP_SERVER,
    get_active_scopes,
    get_current_transport_session_id,
    get_workspace_policy,
    prompt,
    resource,
    tool,
)

_STATE_LOCK = RLock()
_JOBS: JobManager | None = None
_INVESTIGATIONS: InvestigationManager | None = None
_REVISIONS = RevisionTracker()
_TRANSACTIONS = TransactionManager(_REVISIONS)
_REVISION_HOOK: Any = None
_DEBUG_HOOK: Any = None
_DEBUG_SNAPSHOTS: dict[str, dict[str, Any]] = {}


def _ida_synchronized(func):
    """Apply the IDA main-thread wrapper lazily to preserve pure imports."""

    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        from .sync import idasync

        return idasync(func)(*args, **kwargs)

    return wrapped


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


def _legacy_call(name: str, arguments: dict[str, Any] | None = None) -> Any:
    # The active profile removes legacy tools from the externally visible
    # registry, while vNext workflows still use selected legacy implementations
    # internally.  Dispatch against the preserved implementation registry so
    # profile filtering does not break canonical analysis jobs.
    implementation_methods = getattr(MCP_SERVER.tools, "_all_methods", None)
    if isinstance(implementation_methods, dict):
        implementation = implementation_methods.get(name)
        if implementation is None:
            raise VNextError(ErrorCode.NOT_SUPPORTED, f"Legacy tool is not registered: {name}")
        try:
            return implementation(**(arguments or {}))
        except VNextError:
            raise
        except Exception as exc:
            raise VNextError(ErrorCode.NOT_SUPPORTED, f"Legacy tool failed: {name}: {exc}") from exc

    response = MCP_SERVER.tools.dispatch(
        {"jsonrpc": "2.0", "method": name, "params": arguments or {}, "id": None}
    )
    if response and "error" in response:
        error = response["error"]
        data = error.get("data") or {}
        raw_code = data.get("code", ErrorCode.NOT_SUPPORTED.value)
        try:
            code = ErrorCode(raw_code)
        except ValueError:
            code = ErrorCode.NOT_SUPPORTED
        raise VNextError(code, error.get("message", f"Legacy tool failed: {name}"), details=data)
    return response.get("result") if response else None


def _database_id() -> str:
    try:
        import idaapi

        path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        if path:
            return str(Path(path).resolve())
    except Exception:
        pass
    return get_current_transport_session_id() or "active"


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


def _encode_cursor(offset: int) -> str:
    raw = json.dumps({"offset": max(0, offset)}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        offset = int(value["offset"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise VNextError(ErrorCode.INVALID_OPERATION, "Invalid pagination cursor") from exc
    return max(0, offset)


@tool
def server_capabilities() -> dict[str, Any]:
    """Return runtime, IDA, safety, analysis-engine, and schema capabilities."""

    return _ida_capabilities().to_dict()


@tool
def search(
    kind: Annotated[str, "text, regex, bytes, constant, or instruction"],
    targets: Annotated[list[str], "Search values or patterns"],
    limit: Annotated[int, "Maximum results"] = 100,
    cursor: Annotated[str | None, "Opaque continuation cursor"] = None,
) -> dict[str, Any]:
    """Search text, regular expressions, bytes, constants, or instructions."""

    offset = _decode_cursor(cursor)
    normalized = kind.lower()
    if normalized == "text":
        if len(targets) != 1:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Text search accepts one pattern")
        result = _legacy_call("search_text", {"pattern": targets[0], "limit": limit, "start": None, "end": None, "regex": False, "case_sensitive": False, "include": "all", "code_only": False})
    elif normalized == "regex":
        if len(targets) != 1:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Regex search accepts one pattern")
        result = _legacy_call("find_regex", {"pattern": targets[0], "limit": limit, "offset": offset})
    elif normalized == "bytes":
        result = _legacy_call("find_bytes", {"patterns": targets, "limit": limit, "offset": offset})
    elif normalized in {"constant", "instruction"}:
        result = _legacy_call("find", {"type": normalized, "targets": targets, "limit": limit, "offset": offset})
    else:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported search kind: {kind}")
    return ToolEnvelope(result, provenance={"legacy_tool": normalized}).to_dict()


@tool
def memory_read(
    kind: Annotated[str, "bytes, integer, string, or global"],
    queries: Annotated[list[dict[str, Any]] | list[str], "Address or region queries"],
) -> dict[str, Any]:
    """Read static database bytes, integers, strings, or globals."""

    mapping = {
        "bytes": ("get_bytes", "regions"),
        "integer": ("get_int", "queries"),
        "string": ("get_string", "addrs"),
        "global": ("get_global_value", "queries"),
    }
    if kind not in mapping:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported memory read kind: {kind}")
    name, argument_name = mapping[kind]
    return ToolEnvelope(_legacy_call(name, {argument_name: queries}), provenance={"legacy_tool": name}).to_dict()


@tool
def disassemble(
    addr: Annotated[str, "Function name or hexadecimal address"],
    max_instructions: Annotated[int, "Maximum instructions"] = 500,
    offset: Annotated[int, "Instruction offset"] = 0,
    include_total: Annotated[bool, "Include total instruction count"] = False,
) -> dict[str, Any]:
    """Disassemble a function using canonical hexadecimal address output."""

    result = _legacy_call("disasm", {"addr": addr, "max_instructions": max_instructions, "offset": offset, "include_total": include_total})
    return ToolEnvelope(result, provenance={"legacy_tool": "disasm"}).to_dict()


@tool
def signature_create(
    addrs: Annotated[list[str], "Functions or addresses to sign"],
    format: Annotated[str, "Signature format"] = "ida",
    wildcard_operands: Annotated[bool, "Wildcard relocatable operands"] = True,
    max_length: Annotated[int, "Maximum signature length"] = 250,
) -> dict[str, Any]:
    """Create stable byte signatures for functions or address ranges."""

    result = _legacy_call("make_signature_for_function", {"addrs": addrs, "format": format, "wildcard_operands": wildcard_operands, "max_length": max_length})
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
    if mode == "binary_diff":
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Binary diff requires supervisor-level access to two database sessions")
    raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported analysis mode: {mode}")


@tool
def analysis_run(
    mode: Annotated[str, "triage, function, component, batch, deep, or binary_diff"],
    targets: Annotated[list[str], "Seed functions or addresses"] = [],
    options: Annotated[dict[str, Any] | None, "Analysis budgets and mode options"] = None,
) -> dict[str, Any]:
    """Run a bounded analysis inline or as a cancellable deep-analysis job."""

    normalized = mode.lower()
    effective_options = options or {}
    if normalized != "deep":
        return ToolEnvelope(_analysis_sync(normalized, targets, effective_options), provenance={"mode": normalized}).to_dict()

    def run(context: JobContext) -> dict[str, Any]:
        results: list[Any] = []
        context.progress(0.05, "triage")
        results.append(_analysis_sync("triage", [], effective_options))
        total = max(1, len(targets))
        for index, target in enumerate(targets):
            context.check_cancelled()
            results.append(_analysis_sync("function", [target], effective_options))
            context.progress(0.1 + 0.8 * ((index + 1) / total), f"analyzed {target}")
        context.progress(0.95, "assembling result")
        return ToolEnvelope(results, provenance={"mode": "deep", "database": _database_id()}).to_dict()

    return _jobs().submit("analysis.deep", run, database=_database_id(), resumable=True).to_dict(include_result=False)


@tool
def graph_query(
    kind: Annotated[str, "xrefs, calls, or cfg"],
    targets: Annotated[list[str], "Root functions or addresses"],
    max_depth: Annotated[int, "Maximum traversal depth"] = 3,
    limit: Annotated[int, "Maximum nodes or blocks"] = 1000,
) -> dict[str, Any]:
    """Query xrefs, call graphs, or control-flow graphs."""

    if kind == "xrefs":
        result = _legacy_call("xrefs_to", {"addrs": targets, "limit": limit})
    elif kind == "calls":
        result = _legacy_call("callgraph", {"roots": targets, "max_depth": max_depth, "max_nodes": limit, "max_edges": limit * 2, "max_edges_per_func": 100})
    elif kind == "cfg":
        result = _legacy_call("basic_blocks", {"addrs": targets, "max_blocks": limit, "offset": 0})
    else:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported graph kind: {kind}")
    return ToolEnvelope(result, provenance={"kind": kind}).to_dict()


@tool
def dataflow_trace(
    addr: Annotated[str, "Seed address, string, or function"],
    direction: Annotated[str, "forward, backward, or both"] = "forward",
    max_depth: Annotated[int, "Maximum reference depth"] = 3,
) -> dict[str, Any]:
    """Trace data flow, explicitly labeling the engine and fidelity."""

    try:
        from .hexrays_dataflow import trace_microcode

        return trace_microcode(addr, direction=direction, max_depth=max_depth)
    except VNextError as exc:
        if exc.code is not ErrorCode.NOT_SUPPORTED:
            raise
        fallback_warning = f"Hex-Rays microcode unavailable: {exc}"

    legacy_direction = "forward" if direction == "both" else direction
    result = _legacy_call("trace_data_flow", {"addr": addr, "direction": legacy_direction, "max_depth": max_depth})
    graph = AnalysisGraph(
        engine=AnalysisEngine.REFERENCE_FLOW,
        fidelity="reference",
        nodes=list(result.get("nodes", [])) if isinstance(result, dict) else [],
        edges=list(result.get("edges", [])) if isinstance(result, dict) else [],
        unsupported_edges=[
            {"kind": "semantic_def_use", "reason": "Hex-Rays microcode is unavailable"},
            {"kind": "memory_alias", "reason": "reference flow does not model aliases"},
        ],
        warnings=[fallback_warning, "Result is reference flow, not semantic data flow"],
        truncated=bool(result.get("truncated", False)) if isinstance(result, dict) else False,
    )
    return graph.to_dict()


@tool
def taint_analyze(
    sources: Annotated[list[str], "Source addresses or symbols"],
    sinks: Annotated[list[str], "Sink addresses or symbols"],
    max_depth: Annotated[int, "Maximum propagation depth"] = 4,
    sanitizers: Annotated[list[str], "Known sanitizer symbols"] = [],
    options: Annotated[dict[str, Any] | None, "Propagation domains and result budgets"] = None,
) -> dict[str, Any]:
    """Perform bounded microcode or reference-flow taint correlation."""

    traces = [dataflow_trace(source, "forward", max_depth) for source in sources]
    effective_options = options or {}
    max_paths = max(1, min(int(effective_options.get("max_paths", 100)), 1000))
    enabled_domains = set(effective_options.get("domains", ["register", "stack", "global", "memory"]))
    sink_set = {_normalized_match_token(sink) for sink in sinks}
    sanitizer_set = {_normalized_match_token(item) for item in sanitizers}
    hits: list[dict[str, Any]] = []
    sanitizer_annotations: list[dict[str, Any]] = []
    for source, trace in zip(sources, traces):
        nodes = {node["id"]: node for node in trace.get("nodes", []) if "id" in node}
        adjacency: dict[str, list[str]] = {}
        for edge in trace.get("edges", []):
            adjacency.setdefault(str(edge.get("source")), []).append(str(edge.get("target")))
        source_token = _normalized_match_token(source)
        starts = [node_id for node_id, node in nodes.items() if _node_matches(node, {source_token})]
        if not starts and nodes:
            starts = [next(iter(nodes))]
        queue = [(node_id, [node_id]) for node_id in starts]
        visited = set(starts)
        while queue and len(hits) < max_paths:
            node_id, path = queue.pop(0)
            node = nodes[node_id]
            matched_sanitizers = sorted(token for token in sanitizer_set if _node_matches(node, {token}))
            if matched_sanitizers:
                sanitizer_annotations.append(
                    {"source": source, "node": node_id, "sanitizers": matched_sanitizers, "action": "propagation_stopped"}
                )
                continue
            matched_sinks = sorted(token for token in sink_set if _node_matches(node, {token}))
            if matched_sinks:
                domains = sorted(_node_domains([nodes[item] for item in path]) & enabled_domains)
                fidelity = str(trace.get("fidelity", "reference"))
                hits.append(
                    {
                        "source": source,
                        "sinks": matched_sinks,
                        "path": path,
                        "addresses": [nodes[item].get("address") for item in path if nodes[item].get("address")],
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
    return {
        "engine": engines[0] if len(engines) == 1 else "mixed",
        "fidelity": "semantic_intraprocedural" if semantic else "reference_or_mixed",
        "sources": sources,
        "sinks": sinks,
        "sanitizers": sanitizers,
        "domains": sorted(enabled_domains),
        "hits": hits,
        "sanitizer_annotations": sanitizer_annotations,
        "traces": traces,
        "truncated": len(hits) >= max_paths,
        "unsupported_edges": [
            {"kind": "interprocedural_alias", "reason": "callee summaries are not yet available for every call"},
            {"kind": "thread_handoff", "reason": "concurrent taint propagation is not modeled"},
        ],
        "warnings": [] if semantic else ["At least one trace used reference-flow fallback"],
    }


def _normalized_match_token(value: str) -> str:
    text = value.strip().lower()
    try:
        return hex(int(text, 0))
    except ValueError:
        return text


def _node_matches(node: dict[str, Any], tokens: set[str]) -> bool:
    rendered = json.dumps(node, sort_keys=True).lower()
    return any(token and token in rendered for token in tokens)


def _node_domains(nodes: list[dict[str, Any]]) -> set[str]:
    domains: set[str] = set()
    rendered = " ".join(
        f"{node.get('definitions', '')} {node.get('uses', '')}".lower()
        for node in nodes
    )
    if any(marker in rendered for marker in ("stk", "stack", "@sp", " sp")):
        domains.add("stack")
    if any(marker in rendered for marker in ("mem", "[", "global")):
        domains.update({"memory", "global"})
    if rendered.strip():
        domains.add("register")
    return domains


@tool
def job_status(job_id: Annotated[str, "Job identifier"]) -> dict[str, Any]:
    """Return job state and progress without the potentially large result."""

    return _jobs().status(job_id, include_result=False)


@tool
def job_cancel(job_id: Annotated[str, "Job identifier"]) -> dict[str, Any]:
    """Request cooperative cancellation of a queued or running job."""

    return {"job_id": job_id, "cancel_requested": _jobs().cancel(job_id)}


@tool
def job_result(
    job_id: Annotated[str, "Completed job identifier"],
    cursor: Annotated[str | None, "Opaque result cursor"] = None,
    limit: Annotated[int, "Maximum list items"] = 100,
) -> dict[str, Any]:
    """Return a completed result with opaque cursor pagination for lists."""

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
    seeds: Annotated[list[str], "Seed functions, addresses, or strings"] = [],
    budgets: Annotated[dict[str, Any] | None, "Depth and result budgets"] = None,
) -> dict[str, Any]:
    """Start a resumable, evidence-oriented deep investigation."""

    manager = _investigations()
    record = manager.create(objective, database=_database_id(), seeds=seeds)

    def run(context: JobContext) -> dict[str, Any]:
        try:
            context.progress(0.05, "triage")
            triage = _analysis_sync("triage", [], budgets or {})
            analyses = []
            for index, seed in enumerate(seeds):
                context.check_cancelled()
                analyses.append(_analysis_sync("function", [seed], budgets or {}))
                context.progress(0.1 + 0.8 * ((index + 1) / max(1, len(seeds))), f"analyzed {seed}")
            manager.set_state(record.investigation_id, "completed", triage=triage, analyses=analyses)
            return manager.get(record.investigation_id).to_dict()
        except Exception:
            manager.set_state(record.investigation_id, "failed")
            raise

    job = _jobs().submit("investigation.deep", run, database=record.database, resumable=True)
    manager.set_job(record.investigation_id, job.job_id)
    return manager.get(record.investigation_id).to_dict()


@tool
def investigation_get(investigation_id: Annotated[str, "Investigation identifier"]) -> dict[str, Any]:
    """Return persisted investigation state, evidence, and findings."""

    return _investigations().get(investigation_id).to_dict()


@tool
def investigation_add_finding(
    investigation_id: Annotated[str, "Investigation identifier"],
    title: Annotated[str, "Finding title"],
    description: Annotated[str, "Finding description"],
    severity: Annotated[str, "info, low, medium, high, or critical"] = "info",
    confidence: Annotated[float, "Confidence from 0 to 1"] = 0.5,
    evidence: Annotated[list[dict[str, Any]], "Evidence records"] = [],
    tags: Annotated[list[str], "Finding tags"] = [],
) -> dict[str, Any]:
    """Attach a structured, evidence-backed finding to an investigation."""

    manager = _investigations()
    finding = manager.add_finding(
        investigation_id,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        tags=tags,
    )
    return finding.to_dict()


@tool
def investigation_export(
    investigation_id: Annotated[str, "Investigation identifier"],
    format: Annotated[str, "json, markdown, sarif, dot, or mermaid"] = "markdown",
    path: Annotated[str | None, "Optional output path"] = None,
) -> dict[str, Any]:
    """Export an investigation deterministically, optionally writing a file."""

    content = _investigations().export(investigation_id, format)
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
    "save_database": ("idb_save", "path", SafetyScope.FILESYSTEM),
}


def _parse_operations(values: list[dict[str, Any]]) -> list[MutationOperation]:
    operations = []
    for value in values:
        kind = str(value.get("kind", ""))
        target = _OPERATION_TARGETS.get(kind)
        if target is None:
            raise VNextError(ErrorCode.INVALID_OPERATION, f"Unsupported mutation kind: {kind}")
        operations.append(MutationOperation(kind, dict(value.get("arguments", {})), target[2]))
    return operations


def _checkpoint_path(transaction_id: str) -> str:
    cache_root = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    directory = cache_root / "ida-pro-mcp" / "checkpoints"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{transaction_id}.i64"
    _legacy_call("idb_save", {"path": str(path)})
    return str(path)


def _apply_operation(operation: MutationOperation) -> Any:
    tool_name, argument_name, _scope = _OPERATION_TARGETS[operation.kind]
    arguments = operation.arguments
    if argument_name == "item":
        return _legacy_call(tool_name, arguments)
    if argument_name == "path":
        return _legacy_call(tool_name, {"path": arguments.get("path", "")})
    return _legacy_call(tool_name, {argument_name: arguments.get(argument_name, arguments.get("items", arguments))})


def _perform_undo() -> bool:
    try:
        import ida_undo

        callback = getattr(ida_undo, "perform_undo", None)
        return bool(callback and callback())
    except Exception:
        return False


@_ida_synchronized
def _debug_attach(pid: int, event_id: int = -1) -> dict[str, Any]:
    import ida_dbg

    result = int(ida_dbg.attach_process(int(pid), int(event_id)))
    if result <= 0:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Debugger attach failed with result {result}")
    return {"attached": True, "pid": int(pid), "result": result}


@_ida_synchronized
def _debug_pause() -> dict[str, Any]:
    import ida_dbg

    if not ida_dbg.suspend_process():
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Debugger backend refused pause")
    return {"pause_requested": True}


@_ida_synchronized
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
            results.append({"addr": address, "error": f"Unsupported watchpoint kind: {kind}"})
            continue
        try:
            ea = parse_address(address)
            size = max(1, int(item.get("size", 1)))
            ok = bool(ida_dbg.add_bpt(ea, size, watch_types[kind]))
            results.append({"addr": hex(ea), "kind": kind, "size": size, "ok": ok})
        except Exception as exc:
            results.append({"addr": address, "kind": kind, "error": str(exc)})
    return results


@_ida_synchronized
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
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported trace kind: {kind}")
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
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported trace action: {action}")

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


@_ida_synchronized
def _debug_trace_export(path: str, description: str) -> dict[str, Any]:
    import ida_dbg

    if not ida_dbg.save_trace_file(path, description):
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Debugger backend failed to save the trace")
    return {"path": path, "description": description, "saved": True}


@tool
def mutation_preview(
    operations: Annotated[list[dict[str, Any]], "Discriminated mutation operations"],
) -> dict[str, Any]:
    """Validate and stage a mutation batch without changing the database."""

    parsed = _parse_operations(operations)
    preview = _TRANSACTIONS.preview(
        _database_id(),
        parsed,
        enabled_scopes=get_active_scopes(),
        preview_operation=lambda operation: {
            "kind": operation.kind,
            "arguments": operation.arguments,
            "validated": True,
            "before": None,
            "after": operation.arguments,
        },
    )
    return preview.to_dict()


@tool
def mutation_commit(transaction_id: Annotated[str, "Preview transaction identifier"]) -> dict[str, Any]:
    """Commit an unchanged preview after creating a recovery checkpoint."""

    receipt = _TRANSACTIONS.commit(
        transaction_id,
        database=_database_id(),
        enabled_scopes=get_active_scopes(),
        checkpoint=_checkpoint_path,
        apply_operation=_apply_operation,
        undo=_perform_undo,
    )
    return receipt.to_dict()


@tool
def mutation_status(transaction_id: Annotated[str, "Transaction identifier"]) -> dict[str, Any]:
    """Return preview or committed transaction state."""

    return _TRANSACTIONS.status(transaction_id)


@tool
def mutation_rollback(transaction_id: Annotated[str, "Committed transaction identifier"]) -> dict[str, Any]:
    """Use native undo or return a checkpoint requiring database reopen."""

    return _TRANSACTIONS.rollback(transaction_id, rollback_undo=_perform_undo).to_dict()


@tool
def debug_session(action: Annotated[str, "start, attach, detach, terminate, or status"], target: Annotated[dict[str, Any] | None, "Process launch or attach target"] = None) -> dict[str, Any]:
    """Manage debugger lifecycle through one capability-gated tool."""

    mapping = {"start": "dbg_start", "status": "dbg_status", "terminate": "dbg_exit", "detach": "dbg_exit"}
    if action == "attach":
        pid = (target or {}).get("pid")
        if pid is None:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Attach requires target.pid")
        return ToolEnvelope(_debug_attach(int(pid), int((target or {}).get("event_id", -1)))).to_dict()
    name = mapping.get(action)
    if name is None:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported debug session action: {action}")
    return ToolEnvelope(_legacy_call(name, target or {}), provenance={"legacy_tool": name}).to_dict()


@tool
def debug_control(action: Annotated[str, "continue, step_into, step_over, pause, or run_to"], addr: Annotated[str | None, "Run-to address"] = None) -> dict[str, Any]:
    """Control execution of the active debugger session."""

    mapping = {"continue": "dbg_continue", "step_into": "dbg_step_into", "step_over": "dbg_step_over", "run_to": "dbg_run_to"}
    if action == "pause":
        return ToolEnvelope(_debug_pause()).to_dict()
    name = mapping.get(action)
    if name is None:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported debugger control: {action}")
    return ToolEnvelope(_legacy_call(name, {"addr": addr} if action == "run_to" else {}), provenance={"legacy_tool": name}).to_dict()


@tool
def debug_breakpoints(action: Annotated[str, "list, add, delete, toggle, condition, or watch"], items: Annotated[list[dict[str, Any]] | list[str], "Breakpoint addresses or records"] = []) -> dict[str, Any]:
    """List or mutate breakpoints and their conditions."""

    if action == "watch":
        if not all(isinstance(item, dict) for item in items):
            raise VNextError(ErrorCode.INVALID_OPERATION, "Watchpoints require record items")
        return ToolEnvelope(_debug_add_watchpoints(items)).to_dict()
    mapping = {"list": ("dbg_bps", {}), "add": ("dbg_add_bp", {"addrs": items}), "delete": ("dbg_delete_bp", {"addrs": items}), "toggle": ("dbg_toggle_bp", {"items": items}), "condition": ("dbg_set_bp_condition", {"items": items})}
    if action not in mapping:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported breakpoint action: {action}")
    name, arguments = mapping[action]
    return ToolEnvelope(_legacy_call(name, arguments), provenance={"legacy_tool": name}).to_dict()


@tool
def debug_state(include: Annotated[list[str], "registers, stack, breakpoints, or status"] = ["status", "registers", "stack"]) -> dict[str, Any]:
    """Read a consolidated debugger state snapshot."""

    result: dict[str, Any] = {}
    mapping = {"status": "dbg_status", "registers": "dbg_regs", "stack": "dbg_stacktrace", "breakpoints": "dbg_bps"}
    for item in include:
        if item not in mapping:
            raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported debugger state section: {item}")
        result[item] = _legacy_call(mapping[item], {})
    return ToolEnvelope(result).to_dict()


@tool
def debug_memory(action: Annotated[str, "read, write, snapshot, or diff"], regions: Annotated[list[dict[str, Any]], "Live memory regions"], confirm_nonrollbackable: Annotated[bool, "Required for writes"] = False, snapshot_id: Annotated[str | None, "Snapshot identifier for diff"] = None) -> dict[str, Any]:
    """Read or explicitly confirm a non-rollbackable live-memory write."""

    if action == "read":
        return ToolEnvelope(_legacy_call("dbg_read", {"regions": regions}), provenance={"legacy_tool": "dbg_read"}).to_dict()
    if action == "write":
        if not confirm_nonrollbackable:
            raise VNextError(ErrorCode.PROFILE_DENIED, "Live-memory writes require confirm_nonrollbackable=true")
        return ToolEnvelope(_legacy_call("dbg_write", {"regions": regions}), provenance={"legacy_tool": "dbg_write"}).to_dict()
    if action == "snapshot":
        value = _legacy_call("dbg_read", {"regions": regions})
        identifier = str(uuid4())
        _DEBUG_SNAPSHOTS[identifier] = {"database": _database_id(), "regions": regions, "value": value}
        return ToolEnvelope({"snapshot_id": identifier, "regions": regions, "value": value}).to_dict()
    if action == "diff":
        if not snapshot_id or snapshot_id not in _DEBUG_SNAPSHOTS:
            raise VNextError(ErrorCode.INVALID_OPERATION, "A valid snapshot_id is required")
        previous = _DEBUG_SNAPSHOTS[snapshot_id]
        if previous["database"] != _database_id():
            raise VNextError(ErrorCode.INVALID_DATABASE, "Snapshot belongs to another database")
        current = _legacy_call("dbg_read", {"regions": regions or previous["regions"]})
        return ToolEnvelope(
            {
                "snapshot_id": snapshot_id,
                "changed": current != previous["value"],
                "before": previous["value"],
                "after": current,
            }
        ).to_dict()
    raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported debug memory action: {action}")


@tool
def debug_trace(action: Annotated[str, "start, status, stop, or export"], options: Annotated[dict[str, Any] | None, "Trace limits and export options"] = None) -> dict[str, Any]:
    """Manage cancellable execution traces when supported by the runtime."""

    effective = options or {}
    if action == "export":
        if SafetyScope.FILESYSTEM not in get_active_scopes():
            raise VNextError(ErrorCode.PROFILE_DENIED, "Trace export requires filesystem scope")
        path = effective.get("path")
        if not path:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Trace export requires options.path")
        output = get_workspace_policy().resolve(str(path), must_exist=False)
        return ToolEnvelope(
            _debug_trace_export(str(output), str(effective.get("description", "ida-pro-mcp trace")))
        ).to_dict()
    return ToolEnvelope(_debug_trace_action(action, effective)).to_dict()


@tool
def python_execute(mode: Annotated[str, "eval or file"], code: Annotated[str | None, "Python expression or statements"] = None, path: Annotated[str | None, "Python file path"] = None) -> dict[str, Any]:
    """Execute Python only when the isolated python safety scope is enabled."""

    if mode == "eval" and code is not None:
        return ToolEnvelope(_legacy_call("py_eval", {"code": code}), provenance={"legacy_tool": "py_eval"}).to_dict()
    if mode == "file" and path is not None:
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
def compare_binaries(left_database: str, right_database: str) -> str:
    """Cross-database binary comparison workflow."""

    return _prompt("Compare two binaries and explain meaningful code changes.", f"Use analysis_run binary_diff with `{left_database}` and `{right_database}`; correlate symbols, normalized instructions, signatures, callers, callees, and types.")


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
