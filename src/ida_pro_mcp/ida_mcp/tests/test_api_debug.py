"""Tests for runtime code recovery and debugger-tool registration.

These tests exercise the debugger-independent paths of recover_runtime_code
(dry_run planning and input validation). Live recovery requires an active
debugger and is not exercised here.
"""

from ..framework import (
    test,
    skip_test,
    assert_is_list,
    assert_has_keys,
    assert_error,
    get_any_function,
)
from ..rpc import MCP_SERVER
from ..api_debug import recover_runtime_code


@test()
def test_recover_runtime_code_registered():
    """recover_runtime_code is exposed as an MCP tool."""
    assert "recover_runtime_code" in MCP_SERVER.tools.methods


@test()
def test_recover_runtime_code_requires_bounds():
    """A request without size or end is rejected before touching the debugger."""
    result = recover_runtime_code({"addr": "0x1000"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="size or end")


@test()
def test_recover_runtime_code_rejects_bad_end():
    """end <= addr is rejected before touching the debugger."""
    result = recover_runtime_code({"addr": "0x2000", "end": "0x1000"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="greater than")


@test()
def test_recover_runtime_code_rejects_oversized_range():
    """An oversized range is rejected before touching the debugger."""
    result = recover_runtime_code({"addr": "0x1000", "size": 0x80000})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="too large")


@test()
def test_recover_runtime_code_dry_run_plan():
    """dry_run plans without requiring a debugger or modifying the IDB."""
    fn = get_any_function()
    if not fn:
        skip_test("no function available")
    result = recover_runtime_code({"addr": fn, "size": 16, "dry_run": True})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert r.get("dry_run") is True
    assert r.get("ok") is True
    assert_has_keys(r, "planned", "provenance", "rollback")
