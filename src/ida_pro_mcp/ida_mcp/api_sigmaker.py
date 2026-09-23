"""Signature creation tools for IDA Pro MCP.

Generates the shortest unique signature at an address or function entry
(via the vendored _sigmaker engine) in IDA, x64dbg, mask, or bitmask format.
"""

from typing import Annotated, Literal, NotRequired, TypedDict

import idaapi
import ida_funcs

from .rpc import tool
from .sync import idasync
from .utils import normalize_list_input, resolve_address_or_name

from . import _sigmaker as _sm


# ---------------------------------------------------------------------------
# Output format helpers
# ---------------------------------------------------------------------------

_FORMAT_ALIASES = {
    "ida": "ida",
    "x64dbg": "x64dbg",
    "mask": "mask",
    "bitmask": "bitmask",
}


def _resolve_format(fmt: str) -> "str":
    key = fmt.lower().strip()
    if key not in _FORMAT_ALIASES:
        raise ValueError(
            f"Unknown signature format '{fmt}'. "
            f"Valid formats: ida, x64dbg, mask, bitmask"
        )
    return _FORMAT_ALIASES[key]


def _make_config(
    fmt: str,
    wildcard_operands: bool = True,
    continue_outside_function: bool = True,
    max_length: int = 1000,
) -> "object":
    return _sm.SigMakerConfig(
        output_format=_sm.SignatureType(fmt),
        wildcard_operands=wildcard_operands,
        continue_outside_of_function=continue_outside_function,
        wildcard_optimized=False,
        ask_longer_signature=False,
        max_single_signature_length=max_length,
    )


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class MakeSigResult(TypedDict):
    query: str
    addr: str | None
    signature: str | None
    format: str
    unique: NotRequired[bool]
    error: NotRequired[str]


class MakeSigForFunctionResult(TypedDict):
    query: str
    addr: str | None
    name: str | None
    signature: str | None
    format: str
    unique: NotRequired[bool]
    error: NotRequired[str]


def _make_signatures(
    addrs: list[str] | str,
    anchor: Literal["function", "exact"],
    format: str,
    wildcard_operands: bool,
    max_length: int,
) -> list[dict]:
    """Shared body of make_signature (anchor="exact": sign at the address) and
    make_signature_for_function (anchor="function": resolve to the function
    start and report its name)."""
    fmt = _resolve_format(format)
    cfg = _make_config(fmt, wildcard_operands=wildcard_operands, max_length=max_length)
    maker = _sm.SignatureMaker()
    name_key = {"name": None} if anchor == "function" else {}

    results: list[dict] = []
    for addr_str in normalize_list_input(addrs):
        ea = None
        try:
            ea = resolve_address_or_name(addr_str)
            extra = name_key
            if anchor == "function":
                func = ida_funcs.get_func(ea)
                if not func:
                    raise ValueError(f"No function at {hex(ea)}")
                ea = func.start_ea
                extra = {"name": idaapi.get_func_name(ea) or None}
            sig = maker.make_signature(ea, cfg).signature
            # The generator guarantees uniqueness; no post-generation recheck.
            results.append({
                "query": addr_str,
                "addr": hex(ea),
                **extra,
                "signature": f"{sig:{fmt}}",
                "format": format,
                "unique": True,
            })
        except Exception as e:
            results.append({
                "query": addr_str,
                "addr": hex(ea) if ea is not None else None,
                **name_key,
                "signature": None,
                "format": format,
                "error": str(e),
            })
    return results


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@tool
@idasync
def make_signature(
    addrs: Annotated[
        list[str] | str,
        "Address(es) or name(s) to create unique signatures for "
        "(e.g. '0x401000', 'main', or ['0x401000', 'sub_402000'])",
    ],
    format: Annotated[
        str,
        "Output format: 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands for relocatable signatures (default: true)",
    ] = True,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes before giving up (default: 1000)",
    ] = 1000,
) -> list[MakeSigResult]:
    """Prefer signature_create(addrs, ...) for canonical signatures.
    WHEN: shortest unique signature at each exact address, walking instructions with wildcarded operands.
    RETURNS: [{query, addr, signature, format, unique, error}] per address.
    LIMITS: format ida|x64dbg|mask|bitmask (bad format errors); max_length caps walk before giving up."""
    return _make_signatures(addrs, "exact", format, wildcard_operands, max_length)


@tool
@idasync
def make_signature_for_function(
    addrs: Annotated[
        list[str] | str,
        "Function address(es) or name(s) to create signatures for "
        "(e.g. 'main', '0x401000', or ['main', 'sub_402000'])",
    ],
    format: Annotated[
        str,
        "Output format: 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands for relocatable signatures (default: true)",
    ] = True,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes before giving up (default: 1000)",
    ] = 1000,
) -> list[MakeSigForFunctionResult]:
    """Prefer signature_create(addrs, ...) (delegates to this function-anchored form).
    WHEN: shortest unique signature at each function's start (names/addresses resolve to function starts).
    RETURNS: [{query, addr(function start), name, signature, format, unique, error}] per function.
    LIMITS: non-function addresses error; same format/max_length limits as make_signature."""
    return _make_signatures(addrs, "function", format, wildcard_operands, max_length)
