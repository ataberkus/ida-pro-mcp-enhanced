import json
import os
from threading import RLock
from typing import Any, Optional
from ida_pro_mcp.vnext.audit import AuditLog
from ida_pro_mcp.vnext.auth import WorkspacePolicy
from ida_pro_mcp.vnext.contracts import SafetyScope, VNextError
from ida_pro_mcp.vnext.policy import ToolPolicyRegistry, register_builtin_policies
from .zeromcp import (
    McpRpcRegistry,
    McpServer,
    McpToolError,
    McpHttpRequestHandler,
    get_current_request_external_base_url,
)

MCP_UNSAFE: set[str] = set()
MCP_EXTENSIONS: dict[str, set[str]] = {}  # group -> set of function names
# Advertise legacy implementations on the default allow-all profile.
# Quick profiles and --api-profile canonical can still hide them.
LEGACY_TOOLS_ENABLED = True
MCP_SERVER = McpServer("ida-pro-mcp", extensions=MCP_EXTENSIONS)
MCP_POLICY = ToolPolicyRegistry()
register_builtin_policies(MCP_POLICY)
MCP_UNSAFE.update(
    name
    for name, policy in MCP_POLICY.schemas().items()
    if policy.scopes != frozenset({SafetyScope.READ})
)
MCP_AUDIT = AuditLog()
_policy_lock = RLock()
_active_scopes: set[SafetyScope] = {SafetyScope.READ}
_legacy_tools_enabled = False
_workspace_policy = WorkspacePolicy()


def configure_tool_policy(
    *,
    scopes: set[SafetyScope | str] | None = None,
    legacy_tools: bool = False,
) -> None:
    """Set the process-wide policy applied by tools/list and tools/call."""

    global _active_scopes, _legacy_tools_enabled
    with _policy_lock:
        _active_scopes = {
            SafetyScope(scope) for scope in (scopes or {SafetyScope.READ})
        }
        _active_scopes.add(SafetyScope.READ)
        _legacy_tools_enabled = bool(legacy_tools) and LEGACY_TOOLS_ENABLED


def get_active_scopes() -> set[SafetyScope]:
    with _policy_lock:
        return set(_active_scopes)


def configure_workspace_policy(roots) -> None:
    global _workspace_policy
    with _policy_lock:
        _workspace_policy = WorkspacePolicy.from_values(roots)


def get_workspace_policy() -> WorkspacePolicy:
    with _policy_lock:
        return _workspace_policy


def _tool_visible(name: str) -> bool:
    with _policy_lock:
        policy = MCP_POLICY.get(name)
        return (
            MCP_POLICY.visible(name, legacy=_legacy_tools_enabled)
            and policy.scopes <= _active_scopes
        )


def _enrich_tool_schema(name: str, schema: dict) -> dict:
    policy = MCP_POLICY.get(name)
    schema["annotations"] = policy.annotations()
    schema["_meta"] = {
        **schema.get("_meta", {}),
        "ida_mcp": {
            "safety_scopes": sorted(scope.value for scope in policy.scopes),
            "canonical": policy.canonical,
            "deprecated": policy.replacement is not None and not policy.canonical,
            "replacement": policy.replacement,
        },
    }
    return schema


def resolve_tool_paths(name: str, arguments: dict) -> None:
    path_argument = {
        "idb_open": "input_path",
        "idb_save": "path",
        "py_exec_file": "file_path",
    }.get(name)
    if name == "python_execute" and arguments.get("mode") == "file":
        path_argument = "path"
    if name == "investigation_export" and arguments.get("path"):
        path_argument = "path"
    if path_argument and arguments.get(path_argument):
        get_workspace_policy().resolve(
            arguments[path_argument],
            must_exist=name in {"idb_open", "py_exec_file", "python_execute"},
        )


def _guard_tool_call(name: str, arguments: dict) -> None:
    try:
        MCP_POLICY.authorize(name, get_active_scopes())
        if name == "investigation_export" and arguments.get("path"):
            MCP_POLICY.authorize("idb_save", get_active_scopes())
        resolve_tool_paths(name, arguments)
    except VNextError as exc:
        raise McpToolError(
            str(exc),
            code=exc.code.value,
            details=exc.details,
        ) from exc


MCP_SERVER.tool_visibility_filter = _tool_visible
MCP_SERVER.tool_schema_enricher = _enrich_tool_schema
MCP_SERVER.tool_call_guard = _guard_tool_call
MCP_SERVER.resource_subscriptions_supported = True
MCP_SERVER.resource_list_changed_supported = True
MCP_SERVER.tool_list_changed_supported = True

# ============================================================================
# Output Size Limiting
# ============================================================================

OUTPUT_LIMIT_MAX_CHARS = 50000
OUTPUT_CACHE_MAX_SIZE = 100
_output_cache: dict[str, Any] = {}
_download_base_url: str = os.environ.get("IDA_MCP_URL", "http://127.0.0.1:13337")


def set_download_base_url(url: str) -> None:
    global _download_base_url
    _download_base_url = url.rstrip("/")


def get_download_base_url() -> str:
    return get_current_request_external_base_url() or _download_base_url


def get_current_transport_session_id() -> str | None:
    return MCP_SERVER.get_current_transport_session_id()


def _generate_output_id() -> str:
    import uuid

    return str(uuid.uuid4())


OUTPUT_LIMIT_PREVIEW_ITEMS = 10
OUTPUT_LIMIT_PREVIEW_STR_LEN = 1000


def _truncate_value(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return value

    if isinstance(value, str) and len(value) > OUTPUT_LIMIT_PREVIEW_STR_LEN:
        return value[:OUTPUT_LIMIT_PREVIEW_STR_LEN] + f"... [{len(value)} chars total]"

    if isinstance(value, list):
        # IMPORTANT: Do not inject sentinel objects like {"_truncated": "..."} into lists.
        # Many tool schemas constrain list item shapes (additionalProperties: false),
        # so sentinels can break structured output validation. Truncation is reported
        # via _meta.ida_mcp and the download_hint content.
        return [
            _truncate_value(item, depth + 1)
            for item in value[:OUTPUT_LIMIT_PREVIEW_ITEMS]
        ]

    if isinstance(value, dict):
        return {k: _truncate_value(v, depth + 1) for k, v in value.items()}

    return value


def _build_download_meta(output_id: str, total_chars: int) -> dict:
    download_url = f"{get_download_base_url()}/output/{output_id}.json"
    return {
        "output_truncated": True,
        "total_chars": total_chars,
        "output_id": output_id,
        "download_url": download_url,
        "download_hint": f"Output truncated. Run: curl -o .ida-mcp/{output_id}.json {download_url}",
    }


def get_cached_output(output_id: str) -> Optional[Any]:
    return _output_cache.get(output_id)


def _cache_output(output_id: str, data: Any) -> None:
    if len(_output_cache) >= OUTPUT_CACHE_MAX_SIZE:
        oldest_key = next(iter(_output_cache))
        del _output_cache[oldest_key]
    _output_cache[output_id] = data


def _install_tools_call_patch() -> None:
    original = MCP_SERVER.registry.methods["tools/call"]

    def patched(
        name: str, arguments: Optional[dict] = None, _meta: Optional[dict] = None
    ) -> dict:
        response = original(name, arguments, _meta)

        policy = MCP_POLICY.get(name)
        MCP_AUDIT.append(
            tool=name,
            arguments=arguments or {},
            outcome="error" if response.get("isError") else "success",
            session_id=get_current_transport_session_id(),
            safety_scopes=tuple(sorted(scope.value for scope in policy.scopes)),
            error_code=(
                response.get("structuredContent", {}).get("error", {}).get("code")
                if response.get("isError")
                else None
            ),
        )

        if policy.replacement is not None and not policy.canonical:
            metadata = response.setdefault("_meta", {}).setdefault("ida_mcp", {})
            metadata["deprecation"] = {
                "deprecated": True,
                "replacement": policy.replacement,
                "message": f"Legacy tool '{name}' is deprecated; use '{policy.replacement}'.",
                "removal": "next-major",
            }

        if response.get("isError"):
            return response

        structured = response.get("structuredContent")
        if structured is None:
            return response

        serialized = json.dumps(structured)
        if len(serialized) <= OUTPUT_LIMIT_MAX_CHARS:
            return response

        output_id = _generate_output_id()
        _cache_output(output_id, structured)

        preview = _truncate_value(structured)
        download_meta = _build_download_meta(output_id, len(serialized))

        content = [{
            "type": "text",
            "text": json.dumps(preview, separators=(",", ":")),
        }, {
            "type": "text",
            "text": download_meta["download_hint"],
        }]

        return {
            "structuredContent": preview,
            "content": content,
            "isError": False,
            "_meta": {"ida_mcp": download_meta},
        }

    MCP_SERVER.registry.methods["tools/call"] = patched


# Install the output limiting patch
_install_tools_call_patch()


# ============================================================================
# Decorators
# ============================================================================


def tool(func):
    return MCP_SERVER.tool(func)


def resource(uri):
    return MCP_SERVER.resource(uri)


def prompt(func):
    return MCP_SERVER.prompt(func)


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    policy = MCP_POLICY.get(func.__name__)
    if policy.scopes == frozenset({SafetyScope.READ}):
        MCP_POLICY.set_scope(func.__name__, SafetyScope.MODIFY)
    return func


def scope(
    *scopes: SafetyScope,
    destructive: bool = True,
    idempotent: bool = False,
    open_world: bool = False,
):
    """Attach explicit vNext safety metadata to a tool function."""

    def decorator(func):
        MCP_POLICY.set_scope(
            func.__name__,
            *scopes,
            destructive=destructive,
            idempotent=idempotent,
            open_world=open_world,
        )
        if scopes and set(scopes) != {SafetyScope.READ}:
            MCP_UNSAFE.add(func.__name__)
        return func

    return decorator


def ext(group: str):
    """Mark a tool as belonging to an extension group.

    Tools in extension groups are hidden by default. Enable via ?ext=group query param.
    Example: @ext("dbg") marks debugger tools that require ?ext=dbg to be visible.
    """

    def decorator(func):
        if group not in MCP_EXTENSIONS:
            MCP_EXTENSIONS[group] = set()
        MCP_EXTENSIONS[group].add(func.__name__)
        return func

    return decorator


__all__ = [
    "McpRpcRegistry",
    "McpServer",
    "McpToolError",
    "McpHttpRequestHandler",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "MCP_EXTENSIONS",
    "MCP_POLICY",
    "LEGACY_TOOLS_ENABLED",
    "MCP_AUDIT",
    "tool",
    "unsafe",
    "scope",
    "ext",
    "resource",
    "prompt",
    "configure_tool_policy",
    "configure_workspace_policy",
    "get_active_scopes",
    "get_workspace_policy",
    "get_cached_output",
    "set_download_base_url",
    "get_download_base_url",
    "get_current_transport_session_id",
]
