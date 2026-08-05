import argparse
import http.client
import json
import os
import sys
import traceback
import uuid
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

try:
    from .vnext.auth import (
        AuthPolicy,
        create_token,
        default_token_path,
        load_token_file,
        write_token_file,
    )
    from .vnext.contracts import VNextError
except ImportError:
    from vnext.auth import (
        AuthPolicy, create_token, default_token_path, load_token_file, write_token_file
    )
    from vnext.contracts import VNextError

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

def _installer():
    """Lazily import the installer module.

    The installer pulls in optional deps (e.g. tomli_w) that are only needed for
    --install/--uninstall/--config. Importing it eagerly would prevent the bridge
    from running in environments lacking those deps, so we defer it until a
    subcommand actually needs it.
    """
    try:
        from . import installer  # type: ignore
        return installer
    except ImportError:
        import installer  # type: ignore
        return installer

# Load IDA-free helper modules by file path (the ida_mcp package __init__ imports
# idaapi, which is unavailable outside IDA, so we must not import the package).
import importlib.util as _ilu


def _load_helper(mod_name: str, filename: str):
    path = os.path.join(os.path.dirname(__file__), "ida_mcp", filename)
    spec = _ilu.spec_from_file_location(mod_name, path)
    module = _ilu.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


_discovery = _load_helper("ida_mcp_bridge_discovery", "bridge_discovery.py")
_registry = _load_helper("ida_mcp_registry", "registry.py")

IDA_HOST = "127.0.0.1"
IDA_PORT = 13337
BRIDGE_SESSION_ID = str(uuid.uuid4())

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

# Discovery-driven routing table. Rebuilt whenever the live instance set changes.
_tool_table: "_discovery.ToolTable | None" = None
_tool_table_signature: tuple | None = None


def _post_to_ida(payload: bytes, host: str, port: int) -> dict:
    """POST a JSON-RPC payload to an IDA plugin's HTTP server."""
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.request(
            "POST",
            "/mcp",
            payload,
            {
                "Content-Type": "application/json",
                "Mcp-Session-Id": BRIDGE_SESSION_ID,
            },
        )
        response = conn.getresponse()
        raw_data = response.read().decode()
        if response.status >= 400:
            raise RuntimeError(
                f"HTTP {response.status} {response.reason}: {raw_data}"
            )
        return json.loads(raw_data)
    finally:
        conn.close()


def _fetch_tools_for(host: str, port: int) -> list[dict]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}}
    ).encode("utf-8")
    resp = _post_to_ida(payload, host, port)
    result = resp.get("result", resp)
    return result.get("tools", []) if isinstance(result, dict) else []


def _emit_tools_list_changed() -> None:
    # stdio: best-effort notification; supporting clients will refresh tools/list.
    note = json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
    try:
        sys.stdout.write(note + "\n")
        sys.stdout.flush()
    except Exception:
        pass


def _refresh_tool_table():
    """Rebuild the routing table from the live instance set when it changes."""
    global _tool_table, _tool_table_signature
    instances = _discovery.read_registry_dir(_registry.registry_dir())
    prefixes = _discovery.assign_prefixes(instances)
    targets = [
        _discovery.InstanceTarget(id=i.id, host=i.host, port=i.port, prefix=prefixes[i.id])
        for i in instances
    ]
    signature = tuple(sorted((t.id, t.port, t.prefix) for t in targets))
    if _tool_table is None or signature != _tool_table_signature:
        tools_by_id = {}
        for t in targets:
            try:
                tools_by_id[t.id] = _fetch_tools_for(t.host, t.port)
            except Exception:
                tools_by_id[t.id] = []
        _tool_table = _discovery.build_tool_table(targets, tools_by_id)
        changed = _tool_table_signature is not None
        _tool_table_signature = signature
        if changed:
            _emit_tools_list_changed()
    return _tool_table


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry."""
    if isinstance(request, dict):
        request_obj: JsonRpcRequest = request  # type: ignore
    else:
        try:
            parsed = json.loads(request)
        except Exception:
            return dispatch_original(request)
        if not isinstance(parsed, dict):
            return dispatch_original(request)
        request_obj = parsed  # type: ignore

    method = request_obj.get("method")
    if not isinstance(method, str):
        return dispatch_original(request)
    if method == "initialize":
        return dispatch_original(request)
    if method.startswith("notifications/") and method != "notifications/cancelled":
        return dispatch_original(request)

    # Answer tools/list locally from the discovery-driven routing table.
    if method == "tools/list":
        request_id = request_obj.get("id")
        try:
            result = {"tools": _refresh_tool_table().list_tools()}
        except Exception as e:
            result = {"tools": [], "error": str(e)}
        return JsonRpcResponse(
            {"jsonrpc": "2.0", "result": result, "id": request_id}
        )

    # Route tools/call to the instance identified by the tool-name prefix.
    if method == "tools/call":
        request_id = request_obj.get("id")
        params = dict(request_obj.get("params", {}))
        exposed = params.get("name", "")
        table = _refresh_tool_table()
        if exposed == "ida_list_instances":
            items = [
                {"id": t.id, "host": t.host, "port": t.port, "tool_prefix": t.prefix}
                for t in table.targets
            ]
            return JsonRpcResponse(
                {
                    "jsonrpc": "2.0",
                    "result": {"content": [{"type": "text", "text": json.dumps(items)}]},
                    "id": request_id,
                }
            )
        try:
            host, port, inner = _discovery.route_tool_call(table, exposed)
        except KeyError as e:
            # Backward compatibility: no instances discovered, but the caller used
            # an unprefixed tool name — fall back to the legacy single target.
            if not table.targets and not exposed.startswith("ida_"):
                return _post_to_ida(
                    json.dumps(request_obj).encode("utf-8"), IDA_HOST, IDA_PORT
                )
            return JsonRpcResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32602, "message": str(e)},
                    "id": request_id,
                }
            )
        params["name"] = inner  # strip prefix before proxying
        payload = json.dumps({**request_obj, "params": params}).encode("utf-8")
        return _post_to_ida(payload, host, port)

    payload: bytes | str | dict = request
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    elif isinstance(payload, str):
        payload = payload.encode("utf-8")

    try:
        return _post_to_ida(payload, IDA_HOST, IDA_PORT)
    except Exception as e:
        full_info = traceback.format_exc()
        request_id = request_obj.get("id")
        if request_id is None:
            return None  # Notification, no response needed

        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "Failed to complete request to IDA Pro. "
                        f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n"
                        "The request was not retried automatically. "
                        "If this was a mutating operation, verify IDA state before retrying.\n"
                        f"{full_info}"
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )


mcp.registry.dispatch = dispatch_proxy


def main():
    global IDA_HOST, IDA_PORT

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install the MCP Server and IDA plugin. "
        "The IDA plugin is installed immediately. "
        "Optionally specify comma-separated client targets (e.g., 'claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "The IDA plugin is uninstalled immediately. "
        "Optionally specify comma-separated client targets. "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="MCP transport for install: 'streamable-http' (default), 'stdio', or 'sse'. "
        "For running: use stdio (default) or pass a URL (e.g., http://127.0.0.1:8744[/mcp|/sse])",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project"],
        default=None,
        help="Installation scope: 'project' (current directory, default) or 'global' (user-level)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=f"http://{IDA_HOST}:{IDA_PORT}",
        help=f"IDA RPC server to use (default: http://{IDA_HOST}:{IDA_PORT})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List all available MCP client targets",
    )
    parser.add_argument(
        "--auth-token-file",
        type=str,
        default=None,
        help="Bearer token file for non-loopback HTTP transport.",
    )
    parser.add_argument("command", nargs="?", help="Optional command, currently: auth")
    parser.add_argument(
        "command_action", nargs="?", help="Optional command action, currently: init"
    )
    args = parser.parse_args()

    if args.command is not None:
        if (args.command, args.command_action) != ("auth", "init"):
            parser.error("supported command: ida-pro-mcp auth init")
        token_path = Path(args.auth_token_file) if args.auth_token_file else default_token_path()
        token = create_token()
        write_token_file(token_path, token)
        print(f"Created ida-pro-mcp bearer token at {token_path}")
        return

    # Handle --list-clients independently
    if args.list_clients:
        _installer().list_available_clients()
        return

    # Parse IDA RPC server argument
    ida_rpc = urlparse(args.ida_rpc)
    if ida_rpc.hostname is None or ida_rpc.port is None:
        raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
    IDA_HOST = ida_rpc.hostname
    IDA_PORT = ida_rpc.port

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None

    # Validate flag combinations
    if args.scope and not (is_install or is_uninstall):
        print("--scope requires --install or --uninstall")
        return

    if is_install and is_uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if is_install or is_uninstall:
        _installer().run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return

    if args.config:
        _installer().print_mcp_config()
        return

    try:
        transport = args.transport or "stdio"
        if transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            token = os.environ.get("IDA_MCP_AUTH_TOKEN")
            token_path = Path(args.auth_token_file) if args.auth_token_file else None
            if token is None and token_path is None and default_token_path().exists():
                token_path = default_token_path()
            if token is None and token_path is not None:
                token = load_token_file(token_path)
            auth_policy = AuthPolicy(url.hostname, token)
            try:
                auth_policy.validate_configuration()
            except VNextError as exc:
                raise SystemExit(str(exc)) from exc
            if auth_policy.token_required or token:
                mcp.http_authenticator = auth_policy.authorize_header
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
