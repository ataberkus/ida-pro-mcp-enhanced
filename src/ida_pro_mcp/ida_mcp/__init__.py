"""IDA Pro MCP Plugin - Modular Package Version

This package provides MCP (Model Context Protocol) integration for IDA Pro,
enabling AI assistants to interact with IDA's disassembler and decompiler.

Architecture:
- rpc.py: JSON-RPC infrastructure and registry
- mcp.py: MCP protocol server (HTTP/SSE)
- sync.py: IDA synchronization decorator (@idasync)
- utils.py: Shared helpers and TypedDict definitions
- api_*.py: Modular API implementations (75 tools + 24 resources)
"""

# Ignore SIGPIPE to prevent IDA from being killed when an MCP client
# disconnects while the HTTP server is writing a response. IDA's embedded
# Python may not preserve CPython's default SIG_IGN for SIGPIPE.
import signal

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

# Import infrastructure modules
from . import rpc
from . import sync
from . import utils

# Import all API modules to register @tool functions and @resource functions
from . import api_core
from . import api_analysis
from . import api_memory
from . import api_types
from . import api_modify
from . import api_stack
from . import api_debug
from . import api_python
from . import api_resources
from . import api_survey
from . import api_composite
from . import trace as trace
from . import api_sigmaker
from . import api_recovery

# Re-export key components for external use
from .sync import idasync, IDAError, IDASyncError, CancelledError
from .rpc import (
    MCP_AUDIT,
    MCP_POLICY,
    MCP_SERVER,
    MCP_UNSAFE,
    configure_tool_policy,
    configure_workspace_policy,
    prompt,
    resource,
    scope,
    tool,
    unsafe,
)
from .http import IdaMcpHttpRequestHandler
from .api_core import init_caches

# Tracing is enabled explicitly by the host (ida_mcp.py / idalib_server.py)
# after the IDA database is ready; importing this package has no IDB side effects.

__all__ = [
    # Infrastructure modules
    "rpc",
    "sync",
    "utils",
    # API modules
    "api_core",
    "api_analysis",
    "api_memory",
    "api_types",
    "api_modify",
    "api_stack",
    "api_debug",
    "api_python",
    "api_resources",
    "api_survey",
    "api_composite",
    "api_sigmaker",
    "api_vnext",
    "api_recovery",
    # Re-exported components
    "idasync",
    "IDAError",
    "IDASyncError",
    "CancelledError",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "MCP_POLICY",
    "MCP_AUDIT",
    "tool",
    "unsafe",
    "scope",
    "resource",
    "prompt",
    "configure_tool_policy",
    "configure_workspace_policy",
    "IdaMcpHttpRequestHandler",
    "init_caches",
]
