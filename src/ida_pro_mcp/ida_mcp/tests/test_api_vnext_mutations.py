"""IDA-backed regression tests for vNext mutation transactions and findings."""

from contextlib import contextmanager

import ida_bytes
import ida_hexrays
import idaapi
import idc

from ida_pro_mcp.vnext.contracts import ErrorCode, VNextError

from ..framework import skip_test, test
from ..rpc import configure_tool_policy, get_active_scopes

MAIN = 0x123E
CHECK_PW = 0x11A9


@contextmanager
def _scopes(*scopes: str):
    previous = get_active_scopes()
    configure_tool_policy(scopes=set(scopes), legacy_tools=True)
    try:
        yield
    finally:
        configure_tool_policy(scopes=previous, legacy_tools=True)


def _pseudocode(ea: int, *, cached: bool) -> str:
    flags = 0 if cached else ida_hexrays.DECOMP_NO_CACHE
    return str(ida_hexrays.decompile(ea, None, flags))


@test(binary="crackme03.elf")
def test_set_type_commit_refreshes_cached_decompilation():
    """A committed prototype change is visible in callers' cached pseudocode; rollback restores it."""
    from ..api_vnext import mutation_commit, mutation_preview, mutation_rollback

    if not ida_hexrays.init_hexrays_plugin():
        skip_test("Hex-Rays unavailable")
    original_type = idc.get_type(CHECK_PW)
    before = _pseudocode(MAIN, cached=True)  # warm the cache
    with _scopes("read", "annotate"):
        preview = mutation_preview(
            [{"kind": "set_type", "addr": "check_pw", "type": "int check_pw(char *mcp_pw, int mcp_extra)"}]
        )
        operation = preview["operations"][0]
        assert operation["arguments"]["edits"][0]["addr"] == hex(CHECK_PW), operation
        assert operation["validated"] is True and operation["before"][0]["type"] == original_type, operation
        tid = preview["transaction_id"]
        assert mutation_commit(tid)["status"] == "committed"
        try:
            fresh = _pseudocode(MAIN, cached=False)
            assert fresh != before, "prototype change did not affect main"
            assert _pseudocode(MAIN, cached=True) == fresh, "decompile cache still holds the old caller"
        finally:
            assert mutation_rollback(tid)["status"] == "rolled_back"
    assert idc.get_type(CHECK_PW) == original_type
    assert _pseudocode(MAIN, cached=True) == _pseudocode(MAIN, cached=False)


@test(binary="crackme03.elf")
def test_set_type_preview_survives_unrelated_edit():
    """set_type captures before-state, so an unrelated IDB edit does not make the preview stale."""
    from .. import api_vnext
    from ..api_vnext import mutation_commit, mutation_preview, mutation_rollback

    with _scopes("read", "annotate"):
        preview = mutation_preview([{"kind": "set_type", "addr": hex(CHECK_PW), "type": "int check_pw(char *pw)"}])
        api_vnext._REVISIONS.bump(api_vnext._database_id())  # unrelated edit elsewhere
        receipt = mutation_commit(preview["transaction_id"])
        assert receipt["status"] == "committed", receipt
        assert any("re-verified" in warning for warning in receipt["warnings"]), receipt
        mutation_rollback(preview["transaction_id"])


@test(binary="crackme03.elf")
def test_preview_rejects_bad_types_and_unmapped_addresses():
    """Unparsable types and unmapped addresses fail at preview with the operation index."""
    from ..api_vnext import mutation_preview

    bad = [
        [{"kind": "comment", "addr": MAIN, "comment": "ok"}, {"kind": "set_type", "addr": hex(CHECK_PW), "type": "int (((("}],
        [{"kind": "comment", "addr": "0x7ffffffff000", "comment": "x"}],
        [{"kind": "declare_type", "decl": "struct mcp_broken { int a"}],
        [{"kind": "rename", "addr": "no_such_symbol_mcp", "name": "x"}],
    ]
    for operations in bad:
        try:
            mutation_preview(operations)
        except VNextError as exc:
            assert exc.code is ErrorCode.INVALID_OPERATION, exc
            assert f"operation {len(operations) - 1}" in str(exc), str(exc)
        else:
            raise AssertionError(f"preview accepted invalid operations: {operations}")


@test(binary="crackme03.elf")
def test_upsert_enum_and_operand_enum_roundtrip():
    """Annotate scope alone can create an enum, show it on an operand, and roll the operand back."""
    from ..api_vnext import mutation_preview, mutation_rollback

    target = None
    func = idaapi.get_func(MAIN)
    ea = func.start_ea
    while ea < func.end_ea and target is None:
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, ea) <= 0:
            break
        for op_n, op in enumerate(insn.ops):
            if op.type == idaapi.o_void:
                break
            if op.type == idaapi.o_imm:
                target = (ea, op_n, int(op.value))
                break
        ea += insn.size
    if target is None:
        skip_test("main has no immediate operand")
    insn_ea, op_n, value = target
    enum_name = "mcp_test_enum"
    try:
        with _scopes("read", "annotate"):
            created = mutation_preview(
                [{"kind": "upsert_enum", "name": enum_name, "members": [{"name": "MCP_TEST_VALUE", "value": value}]}],
                commit=True,
            )
            assert created["receipt"]["status"] == "committed", created
            assert idc.get_enum(enum_name) != idc.BADADDR
            applied = mutation_preview(
                [{"kind": "set_operand_type", "addr": hex(insn_ea), "op_n": op_n, "operand_kind": "enum", "enum": enum_name}],
                commit=True,
            )
            assert applied["operations"][0]["validated"] is True, applied
            assert ida_bytes.is_enum(ida_bytes.get_flags(insn_ea), op_n)
            assert mutation_rollback(applied["receipt"]["transaction_id"])["status"] == "rolled_back"
            assert not ida_bytes.is_enum(ida_bytes.get_flags(insn_ea), op_n)
    finally:
        enum_id = idc.get_enum(enum_name)
        if enum_id != idc.BADADDR:
            idc.del_enum(enum_id)


@test(binary="crackme03.elf")
def test_append_comment_reaches_pseudocode_and_rolls_back():
    """An appended line comment inside a function shows in pseudocode; rollback removes it."""
    from ..api_vnext import mutation_preview, mutation_rollback

    if not ida_hexrays.init_hexrays_plugin():
        skip_test("Hex-Rays unavailable")
    note = "mcp appended note"
    with _scopes("read", "annotate"):
        receipt = mutation_preview([{"kind": "append_comment", "addr": "0x12d3", "comment": note}], commit=True)["receipt"]
        assert note in _pseudocode(MAIN, cached=False)
        assert mutation_rollback(receipt["transaction_id"])["status"] == "rolled_back"
    assert note not in _pseudocode(MAIN, cached=False)
    assert note not in (idc.get_cmt(0x12D3, False) or "")


@test(binary="crackme03.elf")
def test_define_function_end_resizes_existing_function():
    """define_function with end on an existing function resizes it; rollback restores the bounds."""
    from ..api_vnext import mutation_commit, mutation_preview, mutation_rollback

    original_end = idc.get_func_attr(CHECK_PW, idc.FUNCATTR_END)
    new_end = idc.prev_head(original_end)  # drop the final instruction
    with _scopes("read", "annotate", "modify"):
        preview = mutation_preview([{"kind": "define_function", "addr": "check_pw", "end": hex(new_end)}])
        assert mutation_commit(preview["transaction_id"])["status"] == "committed"
        assert idc.get_func_attr(CHECK_PW, idc.FUNCATTR_END) == new_end
        assert mutation_rollback(preview["transaction_id"])["status"] == "rolled_back"
    assert idc.get_func_attr(CHECK_PW, idc.FUNCATTR_END) == original_end


@test(binary="crackme03.elf")
def test_finding_evidence_aliases_and_bookmark_commit():
    """Evidence accepts addr/text aliases, resolves symbols to hex, and apply_to_idb bookmarks it undoably."""
    from ..api_vnext import _investigations, investigation_add_finding, mutation_rollback

    with _scopes("read", "annotate"):
        record = _investigations().create("mcp evidence test", database=None)
        finding = investigation_add_finding(
            record.investigation_id,
            title="mcp finding",
            description="password check",
            severity="high",
            evidence=[{"addr": "main", "text": "caller"}, {"note": "context only"}],
            apply_to_idb=True,
        )
        assert finding["evidence"][0]["address"] == hex(MAIN), finding
        assert finding["evidence"][0]["description"] == "caller"
        assert finding["evidence"][1]["address"] is None
        assert "apply_error" not in finding, finding
        slots = [slot for slot in range(1024) if idc.get_bookmark(slot) == MAIN]
        assert slots and idc.get_bookmark_desc(slots[0]) == "[high] mcp finding"
        assert mutation_rollback(finding["transaction_id"])["status"] == "rolled_back"
        assert all(idc.get_bookmark_desc(slot) != "[high] mcp finding" for slot in range(1024) if idc.get_bookmark(slot) == MAIN)
        try:
            investigation_add_finding(record.investigation_id, title="t", description="d", evidence=[{"source": "x"}])
        except VNextError as exc:
            assert exc.code is ErrorCode.INVALID_OPERATION
        else:
            raise AssertionError("evidence without address or description was accepted")
