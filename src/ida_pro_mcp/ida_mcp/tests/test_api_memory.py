"""Tests for api_memory API functions."""

from ..framework import (
    test,
    skip_test,
    assert_non_empty,
    assert_is_list,
    assert_shape,
    assert_ok,
    assert_error,
    optional,
    get_first_segment,
    get_data_address,
    get_unmapped_address,
    get_named_address,
)
from ..api_memory import (
    get_bytes,
    get_int,
    get_string,
    get_global_value,
    patch,
    put_int,
)


CRACKME_FORMAT = "0x201f"
CRACKME_DSO_HANDLE = "0x4008"


def _plain_hex_bytes(text: str) -> str:
    return "".join(part.zfill(2) for part in text.replace("0x", "").split()).lower()


@test()
def test_get_bytes_reads_valid_region():
    """get_bytes returns a non-empty hex byte string for a mapped region."""
    seg = get_first_segment()
    if not seg:
        skip_test("binary has no segments")

    start_addr, _ = seg
    result = get_bytes({"addr": start_addr, "size": 16})
    assert_shape(result, [{"addr": str, "data": optional(str), "error": optional(str)}])
    assert_ok(result[0], "data")
    parts = result[0]["data"].split()
    assert len(parts) == 16
    assert all(part.startswith("0x") for part in parts)


@test()
def test_get_bytes_invalid():
    """get_bytes reports an error for an unmapped address."""
    unmapped = get_unmapped_address()
    results = [
        get_bytes({"addr": unmapped, "size": 16}),
        get_int({"addr": unmapped, "ty": "u32"}),
        get_string(unmapped),
    ]
    for result in results:
        assert_is_list(result, min_length=1)
        assert_error(result[0])


@test()
def test_get_int_reads_common_integer_sizes():
    """get_int can read common unsigned integer sizes from a mapped region."""
    seg = get_first_segment()
    if not seg:
        skip_test("binary has no segments")

    start_addr, _ = seg
    for ty, prefix in (
        ("u8", "u8"),
        ("u16", "u16"),
        ("u32", "u32"),
        ("u64", "u64"),
        ("uint32", "u32"),
        ("uint64", "u64"),
        ("uint32_t", "u32"),
        ("int32", "i32"),
    ):
        result = get_int({"addr": start_addr, "ty": ty})
        assert_is_list(result, min_length=1)
        entry = result[0]
        assert entry["addr"] == start_addr
        assert entry["ty"].startswith(prefix), f"{ty} normalized to {entry['ty']!r}"
        assert entry["error"] is None
        assert isinstance(entry["value"], int)

    rejected = get_int({"addr": start_addr, "ty": "uint"})[0]
    assert rejected.get("error")
    assert "Invalid integer class" in rejected["error"]


@test(binary="crackme03.elf")
def test_get_string_reads_known_crackme_format_string():
    """get_string returns the exact known crackme success format string."""
    result = get_string(CRACKME_FORMAT)
    assert_is_list(result, min_length=1)
    assert_ok(result[0], "value")
    assert result[0]["value"] == "Yes, %s is correct!\n"


@test()
def test_get_global_value():
    """get_global_value returns a non-empty representation for a named global."""
    named = get_named_address("format") or get_data_address()
    if not named:
        skip_test("binary has no suitable named or data address")

    query = "format" if get_named_address("format") else named
    result = get_global_value(query)
    assert_is_list(result, min_length=1)
    assert_ok(result[0], "value")
    assert_non_empty(result[0]["value"])


@test(binary="crackme03.elf")
def test_get_global_value_known_format_symbol():
    """get_global_value resolves the crackme format symbol by name."""
    result = get_global_value("format")
    assert_is_list(result, min_length=1)
    assert_ok(result[0], "value")
    assert result[0]["value"] == '"Yes, %s is correct!"'


@test()
def test_patch_roundtrip_changes_and_restores_bytes():
    """patch modifies bytes at an address and restoration returns the original bytes."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    original = get_bytes({"addr": data_addr, "size": 4})[0]
    assert_ok(original, "data")
    original_data = original["data"]
    original_plain = _plain_hex_bytes(original_data)
    replacement = "90 90 90 90"
    if original_plain == replacement.replace(" ", ""):
        replacement = "cc cc cc cc"

    try:
        patched = patch({"addr": data_addr, "data": replacement})[0]
        assert patched.get("ok") is True
        changed = get_bytes({"addr": data_addr, "size": 4})[0]
        assert _plain_hex_bytes(changed["data"]) == replacement.replace(" ", "")
    finally:
        patch({"addr": data_addr, "data": original_plain})

    restored = get_bytes({"addr": data_addr, "size": 4})[0]
    assert _plain_hex_bytes(restored["data"]) == original_plain


@test()
def test_patch_invalid_address():
    """patch reports an error for an unmapped address."""
    result = patch({"addr": get_unmapped_address(), "data": "90"})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["addr"] == get_unmapped_address()
    assert_error(entry, contains="Address range is not mapped")


@test()
def test_patch_straddling_segment_end_is_rejected():
    """A 16-byte patch starting 8 bytes before a segment end fails without writing."""
    import idautils

    from .. import compat

    target = None
    for seg_ea in idautils.Segments():
        info = compat.get_segment_info(seg_ea)
        if info is None or info.end_ea - info.start_ea < 16:
            continue
        # Need a real gap after this segment, otherwise the range is mapped.
        if compat.get_segment_info(info.end_ea) is None:
            target = info
            break
    if target is None:
        skip_test("no segment with a trailing gap")
    addr = target.end_ea - 8
    before = get_bytes({"addr": hex(addr), "size": 8})[0]
    assert_ok(before, "data")
    result = patch({"addr": hex(addr), "data": "90 " * 16})[0]
    assert_error(result, contains="Address range is not mapped")
    after = get_bytes({"addr": hex(addr), "size": 8})[0]
    assert after["data"] == before["data"]


@test()
def test_get_bytes_rejects_oversized_read():
    """get_bytes with a huge size errors with the read limit."""
    seg = get_first_segment()
    if not seg:
        skip_test("binary has no segments")
    result = get_bytes({"addr": seg[0], "size": 10**9})[0]
    assert_error(result, contains="65536")


@test()
def test_patch_invalid_hex_data():
    """patch rejects invalid hexadecimal payloads."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    result = patch({"addr": data_addr, "data": "ZZZZ"})
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test(binary="crackme03.elf")
def test_put_int_roundtrip_u64():
    """put_int writes a 64-bit value that can be read back and restored."""
    original = get_int({"addr": CRACKME_DSO_HANDLE, "ty": "u64"})[0]
    assert_ok(original, "value")
    original_value = original["value"]
    new_value = original_value ^ 0x55

    try:
        written = put_int(
            {"addr": CRACKME_DSO_HANDLE, "ty": "u64", "value": hex(new_value)}
        )[0]
        assert written["ok"] is True
        roundtrip = get_int({"addr": CRACKME_DSO_HANDLE, "ty": "u64"})[0]
        assert roundtrip["value"] == new_value
    finally:
        restore = put_int(
            {"addr": CRACKME_DSO_HANDLE, "ty": "u64", "value": hex(original_value)}
        )[0]
        assert restore["ok"] is True

    restored = get_int({"addr": CRACKME_DSO_HANDLE, "ty": "u64"})[0]
    assert restored["value"] == original_value


@test()
def test_put_int_roundtrip_signed_i16():
    """put_int correctly writes and restores signed 16-bit integers."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    original = get_bytes({"addr": data_addr, "size": 2})[0]
    assert_ok(original, "data")
    original_plain = _plain_hex_bytes(original["data"])

    try:
        written = put_int({"addr": data_addr, "ty": "i16", "value": "-2"})[0]
        assert written["ok"] is True
        roundtrip = get_int({"addr": data_addr, "ty": "i16"})[0]
        assert roundtrip["value"] == -2
    finally:
        patch({"addr": data_addr, "data": original_plain})

    restored = get_bytes({"addr": data_addr, "size": 2})[0]
    assert _plain_hex_bytes(restored["data"]) == original_plain


@test()
def test_put_int_overflow():
    """put_int reports overflow when the value does not fit the target type."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    result = put_int({"addr": data_addr, "ty": "u8", "value": "0x100"})[0]
    assert result["ok"] is False
    assert_error(result, contains="does not fit")


@test()
def test_put_int_invalid_address():
    """put_int rejects writes to unmapped addresses."""
    result = put_int({"addr": get_unmapped_address(), "ty": "u32", "value": "1"})[0]
    assert result["ok"] is False
    assert_error(result, contains="Address range is not mapped")


@test()
def test_get_global_value_not_found():
    """get_global_value reports unknown names with the resolver error."""
    result = get_global_value("definitely_not_a_global_symbol")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Unknown address or symbol 'definitely_not_a_global_symbol'")


@test(binary="crackme03.elf")
def test_memory_read_bytes_compact_hex_and_item_size_default():
    """memory_read bytes returns compact hex; a bare address reads the whole item."""
    import ida_bytes
    import idaapi

    from ..api_vnext import memory_read

    (row,) = memory_read("bytes", ["format"])["data"]
    assert row["size"] == ida_bytes.get_item_size(int(CRACKME_FORMAT, 16))
    assert bytes.fromhex(row["hex"]).startswith(b"Yes, %s is correct!")
    (row,) = memory_read("bytes", [{"addr": "main+0x10", "size": 4}])["data"]
    assert row == {"addr": "main+0x10", "size": 4, "hex": idaapi.get_bytes(0x124E, 4).hex()}


@test(binary="crackme03.elf")
def test_memory_read_integer_shorthand_and_item_size_type():
    """integer accepts 'addr:ty' and bare addresses (ty from the item size)."""
    from ..api_vnext import memory_read

    expected = get_int({"addr": CRACKME_DSO_HANDLE, "ty": "u64"})[0]
    short, bare = memory_read("integer", [f"{CRACKME_DSO_HANDLE}:u64", CRACKME_DSO_HANDLE])["data"]
    assert (short["ty"], short["value"]) == (expected["ty"], expected["value"]), short
    assert (bare["ty"], bare["value"]) == (expected["ty"], expected["value"]), bare


@test(binary="crackme03.elf")
def test_memory_read_patch_diff_reports_function_of_patched_code():
    """patch_diff ranges name the containing function and disappear after restore."""
    from ..api_vnext import memory_read

    probe = "0x1242"  # inside main
    original = _plain_hex_bytes(get_bytes({"addr": probe, "size": 1})[0]["data"])
    replacement = "cc" if original != "cc" else "90"
    try:
        assert patch({"addr": probe, "data": replacement})[0]["ok"] is True
        rows = [r for r in memory_read("patch_diff")["data"] if r["addr"] == probe]
        assert rows == [
            {**rows[0], "size": 1, "original_hex": original, "patched_hex": replacement, "function": "main"}
        ], rows
    finally:
        patch({"addr": probe, "data": original})
    assert all(r["addr"] != probe for r in memory_read("patch_diff")["data"])


@test(binary="typed_fixture.elf")
def test_memory_read_struct_returns_typed_fields():
    """memory_read struct reads named member values for a struct at an address."""
    from ..api_vnext import memory_read

    (row,) = memory_read("struct", [{"addr": "g_wrapper", "struct": "Wrapper"}])["data"]
    members = {m["name"]: m for m in row["members"]}
    assert members["pt"]["type"] == "Point"
    assert "1122334455667788" in members["magic"]["value"]
