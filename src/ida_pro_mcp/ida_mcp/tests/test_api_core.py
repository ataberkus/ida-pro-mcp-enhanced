"""Tests for api_core API functions."""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
    assert_shape,
    assert_ok,
    assert_error,
    is_hex_address,
    list_of,
    optional,
    get_any_function,
    get_data_address,
)
from ..utils import Function, ConvertedNumber
from ..api_core import (
    lookup_funcs,
    int_convert,
    list_globals,
    entity_query,
    imports,
    imports_query,
    server_health,
    server_warmup,
)


CRACKME_MAIN = "0x123e"
CRACKME_CHECK_PW = "0x11a9"
CRACKME_FORMAT = "0x201f"
CRACKME_PRINTF = "0x4040"


@test()
def test_lookup_funcs_by_address():
    """lookup_funcs resolves a valid function address to a complete function object."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = lookup_funcs(fn_addr)
    assert_shape(
        result,
        [
            {
                "query": str,
                "fn": optional(Function),
                "error": optional(str),
            }
        ],
    )
    assert_ok(result[0], "fn")
    fn = result[0]["fn"]
    assert_typed = fn is not None
    assert assert_typed
    assert fn["addr"] == fn_addr
    assert_valid_address(fn["addr"])
    assert_non_empty(fn["name"])


@test(binary="crackme03.elf")
def test_lookup_funcs_known_crackme_symbols():
    """lookup_funcs resolves known crackme symbols to their expected entry addresses."""
    results = lookup_funcs(["main", "check_pw"])
    assert len(results) == 2

    by_query = {item["query"]: item for item in results}
    assert_ok(by_query["main"], "fn")
    assert_ok(by_query["check_pw"], "fn")
    assert by_query["main"]["fn"]["addr"] == CRACKME_MAIN
    assert by_query["check_pw"]["fn"]["addr"] == CRACKME_CHECK_PW


@test()
def test_lookup_funcs_invalid():
    """lookup_funcs reports an error for an invalid address."""
    result = lookup_funcs("0xDEADBEEFDEADBEEF")
    assert_is_list(result, min_length=1)
    assert result[0]["fn"] is None
    assert_error(result[0])


@test()
def test_lookup_funcs_wildcard_returns_non_empty_function_list():
    """lookup_funcs('*') returns a non-empty list of valid functions."""
    result = lookup_funcs("*")
    assert_is_list(result, min_length=1)
    for item in result:
        assert item["query"] == "*"
        assert_ok(item, "fn")
        assert_shape(item["fn"], Function)


@test()
def test_lookup_funcs_empty_returns_non_empty_function_list():
    """lookup_funcs('') behaves like an all-functions query and must not be empty."""
    result = lookup_funcs("")
    assert_is_list(result, min_length=1)
    for item in result:
        assert item["query"] == "*"
        assert_ok(item, "fn")


@test()
def test_lookup_funcs_malformed_hex():
    """lookup_funcs rejects malformed hexadecimal strings."""
    result = lookup_funcs("0xZZZZ")
    assert_is_list(result, min_length=1)
    assert result[0]["fn"] is None
    assert_error(result[0])


@test()
def test_lookup_funcs_data_address():
    """lookup_funcs reports a non-function address as an error."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    result = lookup_funcs(data_addr)
    assert_is_list(result, min_length=1)
    assert result[0]["fn"] is None
    assert_error(result[0])


@test()
def test_lookup_funcs_interior_address():
    """lookup_funcs maps an interior address back to its function entry point."""
    import idaapi
    import idc

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    ea = int(fn_addr, 16)
    func = idaapi.get_func(ea)
    if not func:
        skip_test("IDA could not retrieve the function object")

    interior = idc.next_head(func.start_ea, func.end_ea)
    if interior == idaapi.BADADDR or interior == func.start_ea:
        skip_test("function has no interior instruction")

    result = lookup_funcs(hex(interior))
    assert len(result) == 1
    assert_ok(result[0], "fn")
    assert result[0]["fn"]["addr"] == hex(func.start_ea)
    assert result[0]["fn"]["addr"] != hex(interior)


@test()
def test_int_convert():
    """int_convert returns the expected canonical representations for 0x41."""
    result = int_convert({"text": "0x41"})
    assert_is_list(result, min_length=1)
    assert_shape(
        result,
        [{"input": str, "result": optional(ConvertedNumber), "error": optional(str)}],
    )
    assert_ok(result[0], "result")
    conv = result[0]["result"]
    assert conv["decimal"] == "65"
    assert conv["hexadecimal"] == "0x41"
    assert conv["ascii"] == "A"
    assert conv["bytes"] == "41"


@test()
def test_int_convert_invalid_text():
    """int_convert reports invalid numeric text."""
    result = int_convert({"text": "not_a_number"})
    assert_is_list(result, min_length=1)
    assert result[0]["result"] is None
    assert_error(result[0], contains="Invalid number")


@test()
def test_int_convert_overflow():
    """int_convert reports overflow when the requested size is too small."""
    result = int_convert({"text": "0xFFFF", "size": 1})
    assert_is_list(result, min_length=1)
    assert result[0]["result"] is None
    assert_error(result[0], contains="too big")


@test()
def test_int_convert_non_ascii():
    """int_convert returns ascii=None for non-printable bytes."""
    result = int_convert({"text": "0x01"})
    assert_is_list(result, min_length=1)
    assert_ok(result[0], "result")
    assert result[0]["result"]["ascii"] is None


@test()
def test_int_convert_sign_bit_sizing():
    """int_convert sizes 128 to 2 bytes (80 00)."""
    result = int_convert({"text": "128"})
    assert_is_list(result, min_length=1)
    assert_ok(result[0], "result")
    assert result[0]["result"]["bytes"] == "80 00"


@test()
def test_list_globals_returns_non_empty_results_for_all_query():
    """list_globals('*') returns at least one global item."""
    page = list_globals({"filter": "*", "offset": 0, "count": 50})[0]
    assert_shape(
        page,
        {
            "data": list_of({"addr": is_hex_address, "name": str}, min_length=1),
            "next_offset": optional(int),
        },
    )


@test(binary="crackme03.elf")
def test_list_globals_filter_matches_known_symbol():
    """list_globals can find the known crackme format string symbol."""
    page = list_globals({"filter": "format", "offset": 0, "count": 10})[0]
    assert_is_list(page["data"], min_length=1)
    first = page["data"][0]
    assert first["name"] == "format"
    assert first["addr"] == CRACKME_FORMAT


@test()
def test_imports_returns_non_empty_page():
    """imports returns a non-empty page of typed import objects."""
    page = imports(0, 50)
    assert_shape(
        page,
        {
            "data": list_of(
                {"addr": is_hex_address, "imported_name": str, "module": str},
                min_length=1,
            ),
            "next_offset": optional(int),
        },
    )


@test(binary="crackme03.elf")
def test_imports_contains_printf():
    """imports contains the expected printf import for the crackme fixture."""
    page = imports(0, 50)
    matches = [item for item in page["data"] if item["addr"] == CRACKME_PRINTF]
    assert matches, "expected to find printf import at 0x4040"
    assert "printf" in matches[0]["imported_name"]


@test(binary="crackme03.elf")
def test_entity_query_strings_regex_case_sensitivity():
    """entity_query string regex is case-sensitive by default; case_sensitive=false folds case."""
    query = {"kind": "strings", "regex": "CORRECT", "count": 0}
    assert entity_query(query)[0]["total"] == 0

    page = entity_query({**query, "case_sensitive": False})[0]
    assert page["error"] is None
    by_addr = {row["addr"]: row["text"] for row in page["data"]}
    assert by_addr.get("0x201f") == "Yes, %s is correct!\n"
    assert by_addr.get("0x2034") == "No, %s is not correct.\n"


@test()
def test_entity_query_invalid_regex_reports_error():
    """entity_query reports an invalid regex in the page error instead of raising."""
    page = entity_query({"kind": "strings", "regex": "["})[0]
    assert page["data"] == []
    assert str(page["error"]).startswith("Invalid regex:")


# ============================================================================
# Tests for entity_query / health / warmup
# ============================================================================


@test()
def test_entity_query_functions_projection():
    """entity_query supports generic function query + field projection"""
    result = entity_query(
        {
            "kind": "functions",
            "filter": "*",
            "fields": ["addr", "name"],
            "offset": 0,
            "count": 5,
        }
    )
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "kind", "data", "next_offset", "total", "error")
    if page["data"]:
        assert_has_keys(page["data"][0], "kind", "addr", "name")


@test()
def test_entity_query_functions_sort_by_size():
    """entity_query sorts function rows by numeric size, including hex string sizes."""
    result = entity_query(
        {
            "kind": "functions",
            "filter": "*",
            "sort_by": "size",
            "descending": True,
            "offset": 0,
            "count": 10,
        }
    )
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "kind", "data", "next_offset", "total", "error")
    sizes = [int(str(item["size"]), 0) for item in page["data"]]
    assert sizes == sorted(sizes, reverse=True)


@test()
def test_server_health():
    """server_health returns readiness payload"""
    result = server_health()
    assert_has_keys(
        result,
        "status",
        "uptime_sec",
        "module",
        "imagebase",
        "strings_cache_ready",
        "hexrays_ready",
    )


@test()
def test_server_warmup():
    """server_warmup runs warmup steps and returns health"""
    result = server_warmup(
        wait_auto_analysis=False, build_caches=False, init_hexrays=False
    )
    assert_has_keys(result, "ok", "steps", "health")
    assert_is_list(result["steps"])
@test()
def test_imports():
    """imports returns import list with proper structure"""
    page = imports(0, 100)
    assert_has_keys(page, "data", "next_offset")
    if page["data"]:
        assert_has_keys(page["data"][0], "addr", "imported_name", "module")


@test()
def test_imports_pagination():
    """imports respects pagination parameters"""
    page = imports(0, 5)
    assert len(page["data"]) <= 5


@test()
def test_imports_query():
    """imports_query supports filtered import listing"""
    result = imports_query({"filter": "*", "offset": 0, "count": 10})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    if page["data"]:
        assert_has_keys(page["data"][0], "addr", "imported_name", "module")

