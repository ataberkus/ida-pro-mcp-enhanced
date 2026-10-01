"""Recovery tests: switch tables (C1), patches (C1). Placeholders for C2-C4.

Fixture note: typed_fixture.elf is a Zig-built binary; the switch test below
targets an existing Zig runtime jump table (no fixture rebuild needed).
Build command recorded for a future from-source fixture rebuild:
  zig build-exe tests/typed_fixture.c -O ReleaseSafe -femit-bin=tests/typed_fixture.elf
(checked: current fixture .comment section is a zig-bootstrap clang 20.1.2 build).
"""

from ..api_core import entity_query
from ..api_memory import get_bytes, patch
from ..api_vnext import analysis_run, graph_query, memory_read, search
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


@test(binary="crackme03.elf")
def test_dataflow_trace_global_seed_falls_back_to_reference_flow():
    """dataflow_trace on a data address (no microcode) returns a reference-flow graph."""
    from ..api_vnext import dataflow_trace
    from ..framework import get_data_address

    data_addr = get_data_address()
    if not data_addr:
        skip_test("no data address in fixture")
    graph = dataflow_trace(data_addr, "backward", 1)
    assert graph["engine"] == "reference_flow", f"expected fallback engine: {graph!r}"
    assert any("not inside a function" in warning for warning in graph["warnings"]), graph["warnings"]


@test(binary="crackme03.elf")
def test_mutation_preview_save_database_without_path():
    """save_database with no path means 'save to current IDB' and must preview."""
    from ..api_vnext import mutation_preview

    preview = mutation_preview([{"kind": "save_database"}])
    assert preview["operations"][0]["kind"] == "save_database"
    assert preview["required_scopes"] == ["filesystem"]


@test(binary="typed_fixture.elf")
def test_callsite_args_resolves_field_pointer_argument():
    """callsite_args(sum_point) reports use_wrapper passing &g_wrapper.pt (offset 0)."""
    g_wrapper = get_named_address("g_wrapper")
    if not g_wrapper:
        skip_test("g_wrapper symbol not present")
    page = graph_query("callsite_args", ["sum_point"])["data"][0]
    assert page["count"] == 1, page
    call = page["matches"][0]
    assert call["func_name"] == "use_wrapper", call
    assert int(call["args"][0]["addr"], 16) == int(g_wrapper, 16), call


@test(binary="typed_fixture.elf")
def test_callsite_args_follows_plt_thunk_to_import():
    """callsite_args(puts) resolves the extern through its .plt thunk and decodes the string arg."""
    page = graph_query("callsite_args", ["puts"])["data"][0]
    strings = [arg.get("string") for call in page["matches"] for arg in call["args"]]
    assert "unreachable branch" in strings, page


@test(binary="typed_fixture.elf")
def test_ctree_search_call_arg_predicates():
    """ctree call patterns filter on callee regex and per-argument predicates."""
    hit = search("ctree", ["callee=printf arg0=str arg2=!const"])["data"][0]
    assert hit["count"] == 1, hit
    assert hit["matches"][0]["func_name"] == "main"
    assert hit["matches"][0]["args"][0]["string"] == "%s %d\n"
    miss = search("ctree", ["callee=printf arg0=const"])["data"][0]
    assert miss["matches"] == [], miss


@test(binary="typed_fixture.elf")
def test_ctree_search_comparison_constant():
    """op=cmp value=1000 finds main's `argc > 1000`; unbounded patterns are rejected."""
    from ida_pro_mcp.vnext.contracts import VNextError

    hit = search("ctree", ["op=cmp value=1000"])["data"][0]
    assert [(m["func_name"], m["cmp"]) for m in hit["matches"]] == [("main", ">")], hit
    try:
        search("ctree", ["op=cmp"])
    except VNextError as exc:
        assert "bound the scan" in str(exc)
    else:
        raise AssertionError("unbounded ctree pattern was accepted")


@test(binary="typed_fixture.elf")
def test_crypto_search_finds_patched_aes_sbox():
    """An AES S-box row patched into g_numbers is reported; algorithm filters exclude it."""
    g_numbers = get_named_address("g_numbers")
    if not g_numbers:
        skip_test("g_numbers symbol not present")
    original = get_bytes({"addr": g_numbers, "size": 16})[0]["data"]
    original_hex = "".join(part.zfill(2) for part in original.replace("0x", "").split()).lower()
    try:
        assert patch({"addr": g_numbers, "data": "637c777bf26b6fc53001672bfed7ab76"})[0]["ok"]
        rows = search("crypto", ["aes"])["data"]["matches"]
        assert {"algorithm": "AES", "label": "S-box", "kind": "table"}.items() <= next(
            r for r in rows if int(r["addr"], 16) == int(g_numbers, 16)
        ).items(), rows
        other = search("crypto", ["sha"])["data"]["matches"]
        assert all(int(r["addr"], 16) != int(g_numbers, 16) for r in other), other
    finally:
        patch({"addr": g_numbers, "data": original_hex})


@test(binary="typed_fixture.elf")
def test_crypto_search_finds_unsigned_code_immediate():
    """Patching use_wrapper's `1234` imm32 to TEA's 0x9E3779B9 (>= 2**31) yields an immediate row at that insn."""
    from ..api_analysis import find

    insns = find("immediate", ["0x9E3779B9"])[0]
    assert insns["error"] is None and insns["matches"] == [], insns
    hit = find("immediate", ["1234"])[0]["matches"]
    if not hit:
        skip_test("no 1234 immediate in fixture")
    insn = int(hit[0], 16)
    data = get_bytes({"addr": hex(insn), "size": 16})[0]["data"]
    raw = bytes.fromhex("".join(part.zfill(2) for part in data.replace("0x", "").split()))
    imm_at = insn + raw.index(bytes.fromhex("d2040000"))
    try:
        assert patch({"addr": hex(imm_at), "data": "b979379e"})[0]["ok"]
        rows = search("crypto", ["tea"])["data"]["matches"]
        assert [(r["addr"], r["kind"], r["value"]) for r in rows] == [(hex(insn), "immediate", "0x9e3779b9")], rows
        assert hex(insn) in find("immediate", ["0x9E3779B9"])[0]["matches"]
    finally:
        patch({"addr": hex(imm_at), "data": "d2040000"})


@test(binary="typed_fixture.elf")
def test_emulate_returns_values_and_stubs_imports():
    """use_wrapper -> 279 from IDB globals; sum_point reads a heap struct; main's printf is stubbed."""
    try:
        import unicorn  # noqa: F401
    except ImportError:
        skip_test("unicorn not installed")
    wrapper = analysis_run("emulate", ["use_wrapper"])["data"]["calls"][0]
    assert wrapper["status"] == "returned", wrapper
    assert int(wrapper["return"], 16) == 33 + 44 + ord("B") + 0x88

    point = analysis_run("emulate", ["sum_point"], {"calls": [[{"bytes": "01000000 02000000 03"}]]})["data"]["calls"][0]
    assert point["status"] == "returned", point
    assert int(point["return"], 16) == 6

    main = analysis_run("emulate", ["main"], {"calls": [[1, 0]]})["data"]["calls"][0]
    assert main["status"] == "returned", main
    assert int(main["return"], 16) == 0
    assert [entry["name"] for entry in main["imports"]] == ["printf"], main["imports"]

    starved = analysis_run("emulate", ["use_wrapper"], {"max_insns": 1})["data"]["calls"][0]
    assert starved["status"] == "budget_exhausted", starved
