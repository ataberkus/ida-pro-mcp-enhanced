"""Tests for the Hex-Rays function-review extra feature."""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    get_any_function,
)
from ..api_core import lookup_funcs
from ..api_vnext import mutation_preview
from ..ui_function_review import collect_function_review
from ida_pro_mcp.vnext.function_review import (
    build_cursor_prompt,
    build_mutation_operations,
)


def _require_any_function() -> str:
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    return fn_addr


@test()
def test_function_review_collects_analysis_run_evidence():
    """collect_function_review returns the same evidence shape as analyze_function."""
    fn_addr = _require_any_function()
    review = collect_function_review(int(fn_addr, 16))
    assert_has_keys(review, "addr", "name", "summary", "prompt", "local_rows")
    assert review["addr"] == fn_addr or review["addr"].lower() == fn_addr.lower()
    assert fn_addr in review["prompt"]
    assert "mutation_preview" in review["prompt"]
    assert "analysis_run" in review["prompt"]
    if review.get("error") is None:
        assert_has_keys(review, "strings", "callees", "callers", "decompiled")


@test()
def test_function_review_prompt_matches_helper():
    """Dialog prompt is the shared helper output for the collected analysis."""
    fn_addr = _require_any_function()
    review = collect_function_review(int(fn_addr, 16))
    assert review["prompt"] == build_cursor_prompt(review)


@test()
def test_function_review_preview_does_not_change_names():
    """Staging a rename through mutation_preview must not mutate the IDB."""
    fn_addr = _require_any_function()
    original = lookup_funcs(fn_addr)[0]
    original_name = original["fn"]["name"]
    operations = build_mutation_operations(
        addr=fn_addr,
        current_name=original_name,
        new_name=original_name + "_review",
        comment="review-only",
        current_comment="",
    )
    preview = mutation_preview(operations)
    assert preview.get("transaction_id")
    restored = lookup_funcs(fn_addr)[0]
    assert restored["fn"]["name"] == original_name


@test(binary="crackme03.elf")
def test_mutation_commit_two_renames_then_rollback():
    """Commit two renames, roll back, and both names revert."""
    import idaapi

    from ..rpc import configure_tool_policy, get_active_scopes
    from ..api_vnext import mutation_commit, mutation_rollback
    from ida_pro_mcp.vnext.contracts import SafetyScope

    eas = []
    for ea in __import__("idautils").Functions():
        eas.append(ea)
        if len(eas) == 2:
            break
    if len(eas) < 2:
        skip_test("binary has fewer than two functions")
    originals = [idaapi.get_name(ea) or "" for ea in eas]
    operations = [
        {"kind": "rename", "addr": hex(eas[0]), "name": "__rb_a__"},
        {"kind": "rename", "addr": hex(eas[1]), "name": "__rb_b__"},
    ]
    previous_scopes = get_active_scopes()
    configure_tool_policy(scopes=set(SafetyScope), legacy_tools=True)
    try:
        preview = mutation_preview(operations)
        tid = preview.get("transaction_id")
        assert tid, f"preview failed: {preview}"
        receipt = mutation_commit(tid)
        assert receipt.get("status") == "committed", f"commit failed: {receipt}"
        assert idaapi.get_name(eas[0]) == "__rb_a__"
        assert idaapi.get_name(eas[1]) == "__rb_b__"
        rolled = mutation_rollback(tid)
        assert rolled.get("status") == "rolled_back", f"rollback failed: {rolled}"
        assert idaapi.get_name(eas[0]) == originals[0]
        assert idaapi.get_name(eas[1]) == originals[1]
    finally:
        configure_tool_policy(scopes=previous_scopes, legacy_tools=True)
        for ea, name in zip(eas, originals):
            if idaapi.get_name(ea) != name:
                idaapi.set_name(ea, name, idaapi.SN_NOWARN)
