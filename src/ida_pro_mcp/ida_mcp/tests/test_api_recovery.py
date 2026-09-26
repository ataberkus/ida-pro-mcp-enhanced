"""Recovery tests: switch tables (C1), patches (C1). Placeholders for C2-C4.

Fixture note: typed_fixture.elf is a Zig-built binary; the switch test below
targets an existing Zig runtime jump table (no fixture rebuild needed).
Build command recorded for a future from-source fixture rebuild:
  zig build-exe tests/typed_fixture.c -O ReleaseSafe -femit-bin=tests/typed_fixture.elf
(checked: current fixture .comment section is a zig-bootstrap clang 20.1.2 build).
"""

from ..api_core import entity_query
from ..api_memory import get_bytes, patch
from ..api_vnext import analysis_run, memory_read
from ..framework import assert_has_keys, assert_is_list, assert_valid_address, get_named_address, skip_test, test


@test(binary="typed_fixture.elf")
def test_recovery_switches_enumerate_jump_tables():
    """entity_query(kind="switches") finds a multi-case jump table in the fixture."""
    page = entity_query({"kind": "switches", "count": 0})[0]
    assert page["error"] is None, f"switches query failed: {page['error']}"
    rows = page["data"]
    assert_is_list(rows, min_length=1)
    multi = [row for row in rows if len(row.get("cases", [])) >= 2]
    assert multi, f"expected a switch with >=2 cases, got {len(rows)} rows"
    row = multi[0]
    assert len(row["cases"]) == row["ncases"]
    func_ea = int(row["func"], 16) if str(row.get("func", "")).startswith("0x") else None
    if func_ea is None:
        import idaapi

        func_ea = idaapi.get_name_ea(idaapi.BADADDR, str(row.get("func", "")))
    import ida_funcs

    func = ida_funcs.get_func(func_ea)
    assert func is not None, f"switch func not a function: {row['func']!r}"
    for case in row["cases"]:
        target = int(case["target"], 16)
        assert func.start_ea <= target < func.end_ea, (
            f"case target {case['target']} outside func {row['func']}"
        )


@test(binary="typed_fixture.elf")
def test_recovery_switches_targets_filter():
    """entity_query(kind="switches", targets=[...]) scopes enumeration to one function."""
    all_page = entity_query({"kind": "switches", "count": 0})[0]
    assert all_page["error"] is None
    assert all_page["data"], "expected at least one switch row"
    target_func = all_page["data"][0]["func"]
    page = entity_query({"kind": "switches", "targets": [target_func], "count": 0})[0]
    assert page["error"] is None, f"targets query failed: {page['error']}"
    assert page["data"], "expected switch rows for the targeted function"
    assert {row["func"] for row in page["data"]} == {target_func}


@test()
def test_recovery_patch_roundtrip_lists_and_diffs():
    """patch 1 byte -> patches row (original != patched) -> patch_diff line -> restore."""
    import ida_segment
    import idautils

    probe = None
    for seg_ea in idautils.Segments():
        seg = ida_segment.segment_info_t()
        if seg and ida_segment.get_segment_info(seg, seg_ea) and not (
            seg.get_perm() & ida_segment.SEGPERM_EXEC
        ):
            probe = hex(seg.start_ea)
            break
    if probe is None:
        skip_test("binary has no data segment")

    original = get_bytes({"addr": probe, "size": 1})[0]
    assert original.get("error") is None, f"read failed: {original.get('error')}"
    orig_plain = "".join(part.zfill(2) for part in original["data"].replace("0x", "").split()).lower()
    replacement = "cc" if orig_plain != "cc" else "90"
    try:
        patched = patch({"addr": probe, "data": replacement})[0]
        assert patched.get("ok") is True, f"patch failed: {patched.get('error')}"

        page = entity_query({"kind": "patches"})[0]
        assert page["error"] is None, f"patches query failed: {page['error']}"
        rows = [row for row in page["data"] if row["addr"] == probe]
        assert rows, f"no patches row for {probe}"
        row = rows[0]
        assert row["original"] != row["patched"]
        assert row["original"] == orig_plain
        assert row["patched"] == replacement

        diff = memory_read("patch_diff")
        text = diff["data"]["text"]
        assert f": {orig_plain} {replacement}" in text.lower()
    finally:
        patch({"addr": probe, "data": orig_plain})

    restored = get_bytes({"addr": probe, "size": 1})[0]
    assert "".join(part.zfill(2) for part in restored["data"].replace("0x", "").split()).lower() == orig_plain
    assert entity_query({"kind": "patches"})[0]["data"] == []


@test()
def test_recovery_classes_shape_or_skip():
    """entity_query(kind="classes") recovers RTTI rows; skips when the binary has none."""
    import ida_funcs

    page = entity_query({"kind": "classes", "count": 0})[0]
    assert page["error"] is None, f"classes query failed: {page['error']}"
    rows = page["data"]
    if not rows:
        skip_test("no RTTI")
    assert_is_list(rows, min_length=1)
    for row in rows:
        assert_has_keys(row, "addr", "name", "abi", "bases", "slots")
        assert_valid_address(row["addr"])
        assert row["abi"] in ("msvc", "itanium"), f"bad abi: {row['abi']!r}"
        assert_is_list(row["bases"])
        assert_is_list(row["slots"], min_length=1)
        first = int(row["slots"][0]["addr"], 16)
        func = ida_funcs.get_func(first)
        assert func is not None and int(func.start_ea) == first, (
            f"first slot {row['slots'][0]['addr']} of {row['name']!r} is not a function start"
        )
    vpage = entity_query({"kind": "vtables", "count": 0})[0]
    assert vpage["error"] is None, f"vtables query failed: {vpage['error']}"
    assert [r["addr"] for r in vpage["data"]] == [r["addr"] for r in rows]


@test()
def test_recovery_signatures_list_nonempty():
    """entity_query(kind="signatures") lists processor .sig files with applied flags."""
    page = entity_query({"kind": "signatures", "count": 0})[0]
    assert page["error"] is None, f"signatures query failed: {page['error']}"
    rows = page["data"]
    assert_is_list(rows, min_length=1)
    for row in rows:
        assert_has_keys(row, "addr", "name", "path", "description", "applied")
        assert row["addr"] == "0x0", f"bad addr: {row['addr']!r}"
        assert row["name"], f"empty sig name: {row!r}"
        assert str(row["path"]).lower().endswith(".sig"), f"bad sig path: {row['path']!r}"
        assert isinstance(row["applied"], bool), f"bad applied flag: {row!r}"


@test()
def test_recovery_type_libraries_list_and_load_roundtrip():
    """type_libraries rows carry loaded flags; load one unloaded TIL via preview/commit/rollback."""
    from ida_pro_mcp.vnext.contracts import VNextError

    from ..api_vnext import mutation_commit, mutation_preview, mutation_rollback
    from ..rpc import configure_tool_policy, get_active_scopes
    from ida_pro_mcp.vnext.contracts import SafetyScope

    page = entity_query({"kind": "type_libraries", "count": 0})[0]
    assert page["error"] is None, f"type_libraries query failed: {page['error']}"
    rows = page["data"]
    assert_is_list(rows, min_length=1)
    for row in rows:
        assert_has_keys(row, "addr", "name", "path", "description", "loaded")
        assert row["addr"] == "0x0", f"bad addr: {row['addr']!r}"
        assert row["name"], f"empty til name: {row!r}"
        assert str(row["path"]).lower().endswith(".til"), f"bad til path: {row['path']!r}"
        assert isinstance(row["loaded"], bool), f"bad loaded flag: {row!r}"
    candidates = [row for row in rows if not row["loaded"]]
    if not candidates:
        skip_test("no unloaded TIL on this IDA install")

    previous_scopes = get_active_scopes()
    configure_tool_policy(scopes=set(SafetyScope), legacy_tools=True)
    try:
        # Most listed TILs target other platforms and fail add_til; try each
        # in order until one commits, skipping when none is loadable here.
        committed = None
        failures = 0
        for target in candidates:
            preview = mutation_preview([{"kind": "load_til", "name": target["name"]}])
            tid = preview.get("transaction_id")
            assert tid, f"preview failed: {preview}"
            try:
                receipt = mutation_commit(tid)
            except VNextError as exc:
                if "Failed to load type library" in str(exc):
                    failures += 1
                    continue
                raise
            assert receipt.get("status") == "committed", f"commit failed: {receipt}"
            committed = (tid, target)
            break
        if committed is None:
            skip_test(f"no loadable TIL on this IDA install ({failures} incompatible)")
        tid, target = committed
        again = entity_query({"kind": "type_libraries", "filter": target["name"]})[0]
        assert again["error"] is None, f"re-query failed: {again['error']}"
        match = [row for row in again["data"] if row["name"] == target["name"]]
        assert match, f"TIL vanished after load: {target['name']!r}"
        assert all(row["loaded"] for row in match), f"TIL not loaded after commit: {match!r}"
        rolled = mutation_rollback(tid)
        assert rolled.get("status") == "rolled_back", f"rollback failed: {rolled}"
    finally:
        configure_tool_policy(scopes=previous_scopes, legacy_tools=True)


@test(binary="typed_fixture.elf")
def test_recovery_similar_self_match_top():
    """analysis_run(mode="similar", targets=[main]) ranks main first at 1.0, sorted desc."""
    main = get_named_address("main")
    if not main:
        skip_test("main symbol not present")
    rows = analysis_run("similar", [main])["data"]
    assert_is_list(rows, min_length=1)
    for row in rows:
        assert_has_keys(row, "addr", "name", "score", "insn_count")
        assert_valid_address(row["addr"])
        assert 0.0 <= row["score"] <= 1.0, f"score out of range: {row!r}"
        assert row["insn_count"] > 0, f"bad insn_count: {row!r}"
    assert int(rows[0]["addr"], 16) == int(main, 16), f"top row not main: {rows[0]!r}"
    assert rows[0]["score"] == 1.0, f"self-match score != 1.0: {rows[0]!r}"
    scores = [row["score"] for row in rows]
    assert scores == sorted(scores, reverse=True), "rows not sorted by score desc"
