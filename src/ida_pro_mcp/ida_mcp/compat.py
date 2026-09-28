"""
IDA Pro API Compatibility Layer

This module wraps IDA APIs that differ between IDA 9.0+ and older versions,
providing a unified interface.

Compatibility notes:
- IDA 9.2+: get_func()/func_t* deprecated; prefer get_func_entry_info()/get_func_start()
- IDA 9.0: some idaapi methods removed, uses ida_entry, ida_ida
- IDA 8.5: idaapi.get_inf_structure methods removed, ida_funcs.func_t api update
- IDA 8.4: uses ida_typeinf.get_ordinal_limit
- IDA <8.4: uses idaapi.get_inf_structure, ida_typeinf.get_ordinal_qty, etc.
"""

from __future__ import annotations

import re
import warnings
from typing import TYPE_CHECKING, Callable, cast

import idaapi
import ida_bytes
import ida_funcs
import ida_nalt
import ida_segment
import ida_typeinf

# ============================================================================
# Version resolution
# ============================================================================


def _parse_kernel_version(v: str) -> tuple[int, int, int]:
    # Parse formats like "9.2", "9.2.0", "9.2sp1"
    nums = [int(x) for x in re.findall(r"\d+", v)]
    major = nums[0] if len(nums) > 0 else 0
    minor = nums[1] if len(nums) > 1 else 0
    patch = nums[2] if len(nums) > 2 else 0
    return (major, minor, patch)


if TYPE_CHECKING:
    import ida_entry
    import ida_ida
    import ida_hexrays

    IDA_VERSION: tuple[int, int, int] = cast(tuple[int, int, int], (9, 2, 0))
else:
    IDA_VERSION = _parse_kernel_version(idaapi.get_kernel_version())

IDA_GE_90 = IDA_VERSION >= (9, 0, 0)
IDA_GE_85 = IDA_VERSION >= (8, 5, 0)
IDA_GE_84 = IDA_VERSION >= (8, 4, 0)

# ============================================================================
# Version-gated imports
# ============================================================================

if IDA_GE_90:
    import ida_ida

if IDA_GE_84:
    import ida_entry

if not IDA_GE_84:
    import ida_hexrays

# ============================================================================
# Entry point compatibility
# ============================================================================


def get_entry_qty() -> int:
    if IDA_GE_90:
        return ida_entry.get_entry_qty()
    return ida_nalt.get_entry_qty()


def get_entry_ordinal(idx: int) -> int:
    if IDA_GE_90:
        return ida_entry.get_entry_ordinal(idx)
    return ida_nalt.get_entry_ordinal(idx)


def get_entry(ordinal: int) -> int:
    if IDA_GE_90:
        return ida_entry.get_entry(ordinal)
    return ida_nalt.get_entry(ordinal)


def get_entry_name(ordinal: int) -> str | None:
    if IDA_GE_90:
        return ida_entry.get_entry_name(ordinal)
    return ida_nalt.get_entry_name(ordinal)


# ============================================================================
# Type ordinal compatibility
# ============================================================================


def get_ordinal_limit(til: ida_typeinf.til_t | None = None) -> int:
    if IDA_GE_84:
        return (
            ida_typeinf.get_ordinal_limit(til)
            if til is not None
            else ida_typeinf.get_ordinal_limit()
        )
    return (
        ida_typeinf.get_ordinal_qty(til)
        if til is not None
        else ida_typeinf.get_ordinal_qty()
    )


# ============================================================================
# inf structure compatibility
# ============================================================================


def inf_get_min_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_min_ea()
    return idaapi.get_inf_structure().min_ea


def inf_get_max_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_max_ea()
    return idaapi.get_inf_structure().max_ea


def inf_get_omin_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_omin_ea()
    return idaapi.get_inf_structure().omin_ea


def inf_get_omax_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_omax_ea()
    return idaapi.get_inf_structure().omax_ea


def inf_is_64bit() -> bool:
    if IDA_GE_85:
        return ida_ida.inf_is_64bit()
    return idaapi.get_inf_structure().is_64bit()


# ============================================================================
# Function info compatibility
# ============================================================================


# IDA 9.4 deprecates the func_t-based API (get_func, ida_frame.*), but
# this package still needs func_t for flags/frames/tails and must run on 8.3+.
# Silence those warnings only when raised from this package's modules.
warnings.filterwarnings(
    "ignore",
    message=r"\w+\(\) is deprecated",
    category=DeprecationWarning,
    module=r"(ida_pro_mcp\.)?ida_mcp(\..*)?$",
)


def get_func(ea: int):
    """Return the ``func_t`` containing *ea*, or None."""
    return ida_funcs.get_func(ea)


def get_func_end_ea(func) -> int:
    """Return the exclusive end address for func_t or func_entry_info_t."""
    if func is None:
        return 0
    end = getattr(func, "end_ea", None)
    if isinstance(end, int) and end:
        return int(end)
    start = int(getattr(func, "start_ea", 0) or 0)
    try:
        import idc

        found = int(idc.find_func_end(start))
        if found not in (0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            return found
    except Exception:
        pass
    return start


def get_func_flags(func) -> int:
    """Return function flags from func_t or func_entry_info_t."""
    if func is None:
        return 0
    if hasattr(func, "get_flags"):
        return int(func.get_flags())
    return int(getattr(func, "flags", 0) or 0)


def get_segment_info(ea: int):
    """Return the ``segment_info_t`` containing *ea*, or None."""
    info = ida_segment.segment_info_t()
    return info if ida_segment.get_segment_info(info, ea) else None


def get_segment_perm(seg) -> int:
    """Return SEGPERM_* bits of a segment_info_t or legacy segment_t."""
    getter = getattr(seg, "get_perm", None)
    return int(getter() if getter is not None else seg.perm)


def get_segment_name(ea: int) -> str | None:
    """Return a segment name by address without deprecated APIs."""
    return ida_segment.get_segment_name(ea) or None


def get_func_name(func) -> str | None:
    """Return function name; accepts func_t or func_entry_info_t."""
    # Address-based lookup works for both func_t and func_entry_info_t.
    # func_entry_info_t.get_name() only works when fetched with GFI_NAME.
    return ida_funcs.get_func_name(func.start_ea)


def get_func_prototype(func) -> ida_typeinf.tinfo_t | None:
    """Return function prototype; accepts func_t or func_entry_info_t."""
    # func_t.get_prototype() introduced in 8.5; unavailable on entry-info.
    if IDA_GE_85 and hasattr(func, "get_prototype"):
        try:
            return func.get_prototype()
        except Exception:
            pass

    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
        return tif
    return None


# ============================================================================
# Binary search compatibility
# ============================================================================


def raw_bin_search(
    ea: int,
    max_ea: int,
    data: bytes,
    mask: bytes,
    flags: int = 0,
) -> int:
    # 9.0+ find_bytes natively supports bytes+mask search
    if IDA_GE_90:
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=mask, flags=flags)
    return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)


def make_bytes_searcher(
    pattern: str,
) -> tuple[Callable[[int, int], int] | None, str | None]:
    tokens = pattern.strip().split()
    if not tokens:
        return None, "Empty pattern"

    # 9.0+ search closure
    if IDA_GE_90:
        normalized = " ".join("?" if t in ("??", "?") else t for t in tokens)

        def _search_modern(ea: int, max_ea: int) -> int:
            return ida_bytes.find_bytes(normalized, ea, range_end=max_ea)

        return _search_modern, None

    # Legacy search closure
    pat = bytearray()
    msk = bytearray()
    for t in tokens:
        if t in ("??", "?"):
            pat.append(0)
            msk.append(0)
            continue
        body = t[2:] if t[:2] in ("0x", "0X") else t
        if len(body) not in (1, 2) or any(ch not in "0123456789abcdefABCDEF" for ch in body):
            return None, f"Invalid byte token: {t!r}"
        value = int(body, 16)
        if value < 0 or value > 0xFF:
            return None, f"Invalid byte token: {t!r}"
        pat.append(value)
        msk.append(0xFF)

    data = bytes(pat)
    mask = bytes(msk)
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW

    def _search_legacy(ea: int, max_ea: int) -> int:
        return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)

    return _search_legacy, None


# ============================================================================
# Type inference compatibility
# ============================================================================


def guess_tinfo(tif: ida_typeinf.tinfo_t, ea: int) -> bool:
    # Prefer modern API first
    try:
        rc = ida_typeinf.guess_tinfo(tif, ea)
        if isinstance(rc, bool):
            if rc:
                return True
        elif int(rc) > 0:
            return True
    except Exception:
        pass

    # Fallback to ida_hexrays for very old IDA
    if not IDA_GE_84 and ida_hexrays is not None:
        try:
            if ida_hexrays.init_hexrays_plugin() and ida_hexrays.guess_tinfo(tif, ea):
                return True
        except Exception:
            pass

    return False
