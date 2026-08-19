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
