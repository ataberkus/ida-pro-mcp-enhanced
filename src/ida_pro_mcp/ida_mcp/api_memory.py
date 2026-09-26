"""Memory reading and writing operations for IDA Pro MCP.

This module provides batch operations for reading and writing memory at various
granularities (bytes, integers, strings) and patching binary data.
"""

import re

from typing import Annotated
import ida_bytes
import idaapi

from .rpc import tool, unsafe
from . import compat
from .sync import IDAError, idasync
from .utils import (
    IntRead,
    IntWrite,
    MemoryPatch,
    MemoryRead,
    normalize_list_input,
    parse_address,
)


def _resolve_read_address(addr: str | int) -> int:
    from .utils import resolve_address_or_name

    try:
        return resolve_address_or_name(addr)
    except IDAError as exc:
        raise ValueError(str(exc)) from exc


MAX_READ_BYTES = 65536
MAX_PATCH_BYTES = 65536


def _require_mapped_range(ea: int, size: int, label: str) -> None:
    cursor = ea
    end_ea = ea + size
    while cursor < end_ea:
        segment = compat.get_segment_info(cursor)
        if segment is None:
            raise ValueError(f"Address range is not mapped: {label}")
        cursor = min(end_ea, segment.end_ea)


def _read_mapped_bytes(addr: str | int, size: int) -> bytes:
    if size <= 0:
        raise ValueError("Read size must be positive")
    ea = _resolve_read_address(addr)
    _require_mapped_range(ea, size, str(addr))
    data = ida_bytes.get_bytes(ea, size)
    if data is None or len(data) != size:
        raise ValueError(f"Failed to read {size} bytes at {addr}")
    return data


# ============================================================================
# Memory Reading Operations
# ============================================================================


@tool
@idasync
def get_bytes(regions: list[MemoryRead] | MemoryRead) -> list[dict]:
    """Prefer memory_read(kind="bytes", queries=...).
    WHEN: read raw bytes from mapped static addresses (memory_read bytes delegates here).
    RETURNS: [{addr, data(hex str), error?}] per region.
    LIMITS: size max 65536; unmapped range raises error entry; static IDB bytes, not live debuggee (see debug_memory)."""
    if isinstance(regions, dict):
        regions = [regions]

    results = []
    for item in regions:
        addr = item.get("addr", "")
        size = item.get("size", 0)

        try:
            if int(size) > MAX_READ_BYTES:
                raise ValueError(f"Read size {int(size)} exceeds limit {MAX_READ_BYTES}")
            data = _read_mapped_bytes(addr, int(size))
            rendered = " ".join(f"{x:#02x}" for x in data)
            results.append({"addr": addr, "data": rendered})
        except Exception as e:
            results.append({"addr": addr, "data": None, "error": str(e)})

    return results


_INT_CLASS_RE = re.compile(
    r"^(?:(?P<unsigned>u(?:int)?)|(?P<signed>i(?:nt)?))"
    r"(?P<bits>8|16|32|64)"
    r"(?:_t)?"
    r"(?P<endian>le|be)?$"
)


def _parse_int_class(text: str) -> tuple[int, bool, str, str]:
    if not text:
        raise ValueError("Missing integer class")

    cleaned = text.strip().lower()
    match = _INT_CLASS_RE.match(cleaned)
    if not match:
        raise ValueError(f"Invalid integer class: {text}")

    bits = int(match.group("bits"))
    signed = match.group("signed") is not None
    endian = match.group("endian") or "le"
    byte_order = "little" if endian == "le" else "big"
    normalized = f"{'i' if signed else 'u'}{bits}{endian}"
    return bits, signed, byte_order, normalized


def _parse_int_value(text: str, signed: bool, bits: int) -> int:
    if text is None:
        raise ValueError("Missing integer value")

    value_text = str(text).strip()
    try:
        value = int(value_text, 0)
    except ValueError:
        raise ValueError(f"Invalid integer value: {text}")

    if not signed and value < 0:
        raise ValueError(f"Negative value not allowed for u{bits}")

    return value


@tool
@idasync
def get_int(
    queries: Annotated[
        list[IntRead] | IntRead,
        "Integer read requests (ty, addr). ty: u8/u32/uint32/i16le/u64be/etc",
    ],
) -> list[dict]:
    """Prefer memory_read(kind="integer", queries=...).
    WHEN: read typed integers ({addr, ty}) from mapped static addresses (memory_read integer delegates here).
    RETURNS: [{addr, ty(normalized), value, error}] per query.
    LIMITS: ty must match u8..u64/i8..i64 with optional le/be; static bytes only."""
    if isinstance(queries, dict):
        queries = [queries]

    results = []
    for item in queries:
        addr = item.get("addr", "")
        ty = item.get("ty", "")

        try:
            bits, signed, byte_order, normalized = _parse_int_class(ty)
            size = bits // 8
            data = _read_mapped_bytes(addr, size)

            value = int.from_bytes(data, byte_order, signed=signed)
            results.append(
                {"addr": addr, "ty": normalized, "value": value, "error": None}
            )
        except Exception as e:
            results.append({"addr": addr, "ty": ty, "value": None, "error": str(e)})

    return results


@tool
@idasync
def get_string(
    addrs: Annotated[list[str] | str, "Addresses or names to read strings from"],
) -> list[dict]:
    """Prefer memory_read(kind="string", queries=...).
    WHEN: read the C string literal at mapped static addresses/names (memory_read string delegates here).
    RETURNS: [{addr, value, error}] per address.
    LIMITS: no literal at addr returns error entry; for bulk strings across the IDB use entity_query(kind="strings")."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = _resolve_read_address(addr)
            if compat.get_segment_info(ea) is None:
                raise ValueError(f"Address is not mapped: {addr}")
            raw = idaapi.get_strlit_contents(ea, -1, 0)
            if not raw:
                results.append(
                    {"addr": addr, "value": None, "error": "No string at address"}
                )
                continue
            value = raw.decode("utf-8", errors="replace")
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


MAX_GLOBAL_VALUE_BYTES = 4096


def get_global_variable_value_internal(ea: int) -> str:
    import ida_typeinf
    import ida_nalt
    import ida_bytes
    from .sync import IDAError

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")

        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
    else:
        size = tif.get_size()

    if size > MAX_GLOBAL_VALUE_BYTES:
        return f"<too large: {size} bytes>"

    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        raw = idaapi.get_strlit_contents(ea, -1, 0)
        if not raw:
            return '""'
        if len(raw) > MAX_GLOBAL_VALUE_BYTES:
            raw = raw[:MAX_GLOBAL_VALUE_BYTES]
            return f'"{raw.decode("utf-8", errors="replace").strip()}..."'
        return_string = raw.decode("utf-8", errors="replace").strip()
        return f'"{return_string}"'
    elif size == 1:
        return hex(ida_bytes.get_byte(ea))
    elif size == 2:
        return hex(ida_bytes.get_word(ea))
    elif size == 4:
        return hex(ida_bytes.get_dword(ea))
    elif size == 8:
        return hex(ida_bytes.get_qword(ea))
    else:
        return " ".join(hex(x) for x in ida_bytes.get_bytes(ea, size))


@tool
@idasync
def get_global_value(
    queries: Annotated[
        list[str] | str, "Global variable addresses or names to read values from"
    ],
) -> list[dict]:
    """Prefer memory_read(kind="global", queries=...).
    WHEN: read one typed global's current value by name/address (memory_read global delegates here).
    RETURNS: [{query, value(rendered str), error}] per query.
    LIMITS: >4096-byte values return "<too large>"; untyped/unknown names return error entries."""
    from .utils import resolve_address_or_name

    queries = normalize_list_input(queries)
    results = []

    for query in queries:
        try:
            try:
                ea = resolve_address_or_name(query)
            except IDAError:
                results.append({"query": query, "value": None, "error": "Not found"})
                continue

            value = get_global_variable_value_internal(ea)
            results.append({"query": query, "value": value, "error": None})
        except Exception as e:
            results.append({"query": query, "value": None, "error": str(e)})

    return results


# ============================================================================
# Batch Data Operations
# ============================================================================


@tool
@idasync
@unsafe
def patch(patches: list[MemoryPatch] | MemoryPatch) -> list[dict]:
    """Prefer mutation_preview(kind="patch_bytes", ...).
    WHEN: direct byte patch (UNSAFE, non-rollbackable); preview first unless already approved.
    RETURNS: [{addr, size, ok, error}] per patch.
    LIMITS: patch data max 65536 bytes; address must be mapped; committed immediately, not staged."""
    if isinstance(patches, dict):
        patches = [patches]

    results = []

    for patch in patches:
        try:
            ea = parse_address(patch["addr"])
            data = bytes.fromhex(patch["data"])

            if len(data) > MAX_PATCH_BYTES:
                raise ValueError(f"Patch size {len(data)} exceeds limit {MAX_PATCH_BYTES}")
            _require_mapped_range(ea, len(data), hex(ea))

            ida_bytes.patch_bytes(ea, data)
            results.append(
                {"addr": patch["addr"], "size": len(data), "ok": True, "error": None}
            )

        except Exception as e:
            results.append({"addr": patch.get("addr"), "size": 0, "error": str(e)})

    return results


@tool
@idasync
@unsafe
def put_int(
    items: Annotated[
        list[IntWrite] | IntWrite,
        "Integer write requests (ty, addr, value). value is a string; supports 0x.. and negatives",
    ],
) -> list[dict]:
    """Prefer mutation_preview(kind="write_integer", ...).
    WHEN: direct typed-integer write (UNSAFE, non-rollbackable); preview first unless already approved.
    RETURNS: [{addr, ty(normalized), value, ok, error}] per item.
    LIMITS: value must fit ty (u8..u64/i8..i64, le/be); address must be mapped."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr = item.get("addr", "")
        ty = item.get("ty", "")
        value_text = item.get("value")

        try:
            bits, signed, byte_order, normalized = _parse_int_class(ty)
            value = _parse_int_value(value_text, signed, bits)
            size = bits // 8
            try:
                data = value.to_bytes(size, byte_order, signed=signed)
            except OverflowError:
                raise ValueError(f"Value {value_text} does not fit in {normalized}")

            ea = parse_address(addr)
            _require_mapped_range(ea, size, hex(ea))
            ida_bytes.patch_bytes(ea, data)
            results.append(
                {
                    "addr": addr,
                    "ty": normalized,
                    "value": str(value_text),
                    "ok": True,
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "ty": ty,
                    "value": str(value_text) if value_text is not None else None,
                    "ok": False,
                    "error": str(e),
                }
            )

    return results
