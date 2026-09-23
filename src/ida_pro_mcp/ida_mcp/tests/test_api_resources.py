"""Tests for api_resources MCP resource functions."""

from ..framework import (
    test,
    skip_test,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
)
from ..api_resources import (
    idb_metadata_resource,
    idb_entrypoints_resource,
    cursor_resource,
    selection_resource,
)
from ..sync import IDAError


CRACKME_MAIN = "0x123e"
CRACKME_CHECK_PW = "0x11a9"


@test(binary="crackme03.elf")
def test_resource_idb_metadata():
    """idb_metadata_resource returns crackme metadata with valid hashes and addresses."""
    result = idb_metadata_resource()
    assert_non_empty(result["path"])
    assert result["module"] == "crackme03.elf"
    assert_valid_address(result["base"])
    assert_valid_address(result["size"])
    assert len(result["md5"]) == 32
    assert len(result["sha256"]) == 64


@test(binary="crackme03.elf")
def test_resource_idb_entrypoints_contains_known_symbols():
    """idb_entrypoints_resource exposes the known crackme entrypoints."""
    result = idb_entrypoints_resource()
    assert_is_list(result, min_length=1)
    by_name = {entry["name"]: entry["addr"] for entry in result}
    assert by_name.get("main") == CRACKME_MAIN
    assert by_name.get("check_pw") == CRACKME_CHECK_PW


@test()
def test_resource_cursor():
    """cursor_resource returns a structured cursor object or a runtime skip in unsupported mode."""
    try:
        result = cursor_resource()
    except IDAError as e:
        skip_test(str(e))
    assert_valid_address(result["addr"])
    if "function" in result:
        assert_valid_address(result["function"]["addr"])
        assert_non_empty(result["function"]["name"])


@test()
def test_resource_selection():
    """selection_resource returns either a selection range or an explicit null selection."""
    try:
        result = selection_resource()
    except IDAError as e:
        skip_test(str(e))
    if "selection" in result:
        assert result["selection"] is None
    else:
        assert_valid_address(result["start"])
        if result["end"] is not None:
            assert_valid_address(result["end"])
