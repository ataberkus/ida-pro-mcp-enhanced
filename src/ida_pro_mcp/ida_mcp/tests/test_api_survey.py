"""Tests for api_survey API functions."""

import re

from ..framework import (
    test,
    assert_has_keys,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
)
from ..api_survey import survey_binary
from ..sync import IDAError


# ============================================================================
# survey_binary tests
# ============================================================================


@test()
def test_survey_binary_metadata_structure():
    """survey_binary metadata contains expected file/arch info."""
    result = survey_binary()
    meta = result["metadata"]
    assert_has_keys(
        meta, "path", "module", "arch", "base_address", "image_size", "md5", "sha256"
    )
    assert_valid_address(meta["base_address"])
    assert_valid_address(meta["image_size"])
    assert meta["arch"] in ("32", "64")
    assert_non_empty(meta["module"])


@test()
def test_survey_binary_segments_structure():
    """survey_binary segments are properly structured with permissions."""
    segments = survey_binary()["segments"]
    assert_is_list(segments, min_length=1)
    for seg in segments:
        assert_valid_address(seg["start"])
        assert re.fullmatch(r"r?w?x?|---", seg["permissions"]), seg


@test()
def test_survey_binary_entrypoints_ordinal_only_for_exports():
    """entrypoints carry `ordinal` only when it differs from the address."""
    for ep in survey_binary()["entrypoints"]:
        assert_valid_address(ep["addr"])
        if "ordinal" in ep:
            assert ep["ordinal"] != int(ep["addr"], 16), ep


@test()
def test_survey_binary_detail_levels():
    """fast is compact (no call graph), full adds it; aliases map; unknown levels error."""
    fast = survey_binary()
    full = survey_binary(detail_level="full")
    assert "call_graph_summary" not in fast
    assert len(fast["interesting_functions"]) <= 10
    assert len(full["interesting_functions"]) <= 25
    for cat in fast["imports_by_category"].values():
        assert len(cat["items"]) <= 5 and cat["count"] >= len(cat["items"]) > 0
    cg = full["call_graph_summary"]
    assert len(cg["root_functions"]) <= 25 and cg["root_count"] >= len(cg["root_functions"])
    assert survey_binary(detail_level="minimal").keys() == fast.keys()
    assert survey_binary(detail_level="standard").keys() == full.keys()
    try:
        survey_binary(detail_level="bogus")
    except IDAError as exc:
        assert "fast" in str(exc) and "full" in str(exc)
    else:
        raise AssertionError("unknown detail_level must raise")


@test(binary="crackme03.elf")
def test_survey_binary_crackme_functions_skip_stubs():
    """crackme03 triage lists main and check_pw, never PLT thunks/import stubs."""
    funcs = survey_binary()["interesting_functions"]
    by_name = {f["name"]: f for f in funcs}
    assert "main" in by_name and "check_pw" in by_name, list(by_name)
    assert "main" in by_name["main"]["reasons"]
    assert int(by_name["check_pw"]["addr"], 16) == 0x11A9
    for f in funcs:
        assert not f["name"].startswith((".", "sub_10")), f
        assert f["name"] not in ("printf", "puts", "strlen", "__libc_start_main"), f


@test(binary="crackme03.elf")
def test_survey_binary_crackme_strings_skip_loader_noise():
    """crackme03 strings include the success message and no loader/version strings."""
    strings = [s["string"] for s in survey_binary()["interesting_strings"]]
    assert any("Yes, %s is correct!" in s for s in strings), strings
    for s in strings:
        assert not s.startswith("GLIBC_") and "ld-linux" not in s, strings
        assert s not in ("__libc_start_main", "libc.so.6", "printf", "puts"), strings
