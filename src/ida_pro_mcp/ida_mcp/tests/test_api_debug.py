"""Tests for debugger-tool registration and debugger-independent paths.

Most debugger tools require a live debugger and are not exercised here.
These tests cover the paths that work without one: tool registration,
capability gating, and pre-debugger validation.
"""

from ..framework import test, assert_has_keys
from ..rpc import MCP_EXTENSIONS, MCP_SERVER, MCP_UNSAFE
from ..sync import IDAError
from .. import api_debug

DEBUG_TOOLS = {
    "dbg_status",
    "dbg_start",
    "dbg_exit",
    "dbg_detach",
    "dbg_continue",
    "dbg_run_to",
    "dbg_step_into",
    "dbg_step_over",
    "dbg_bps",
    "dbg_add_bp",
    "dbg_delete_bp",
    "dbg_toggle_bp",
    "dbg_regs",
    "dbg_stacktrace",
    "dbg_read",
    "dbg_write",
}


@test()
def test_debugger_tools_registered():
    """Every debugger tool is registered as an MCP tool."""
    implementation_tools = getattr(MCP_SERVER.tools, "_all_methods", MCP_SERVER.tools.methods)
    extension_tools = MCP_EXTENSIONS.get("dbg", set())
    for name in sorted(DEBUG_TOOLS):
        assert name in implementation_tools, f"{name} not registered"
        assert name in extension_tools, f"{name} missing dbg extension metadata"


@test()
def test_debugger_tools_marked_unsafe():
    """Debugger tools are unsafe (capability-gated) by default."""
    for name in sorted(DEBUG_TOOLS):
        assert name in MCP_UNSAFE, f"{name} not marked unsafe"


@test()
def test_dbg_status_reports_not_running_without_debugger():
    """dbg_status works without a debugger and reports not_running."""
    result = api_debug.dbg_status()
    assert_has_keys(result, "state")
    assert result["state"] == "not_running"


@test()
def test_dbg_regs_require_running_debugger():
    """Register reads are rejected before touching the debugger."""
    try:
        api_debug.dbg_regs()
    except IDAError as exc:
        assert "not running" in str(exc), f"unexpected error: {exc}"
        return
    raise AssertionError("dbg_regs did not raise without a debugger")


@test()
def test_dbg_read_rejects_without_debugger():
    """Memory reads are rejected before touching the debugger."""
    try:
        api_debug.dbg_read({"addr": "0x1000", "size": 16})
    except IDAError as exc:
        assert "not running" in str(exc), f"unexpected error: {exc}"
        return
    raise AssertionError("dbg_read did not raise without a debugger")
