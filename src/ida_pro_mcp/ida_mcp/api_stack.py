"""Stack frame operations for IDA Pro MCP.

This module provides batch operations for managing stack frame variables,
including reading, creating, and deleting stack variables in functions.
"""

from typing import Annotated
import ida_typeinf
import ida_frame
import ida_funcs

from .rpc import tool, unsafe
from .sync import idasync
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    StackVarDecl,
    StackVarDelete,
    get_stack_frame_variables_internal,
)


# ============================================================================
# Stack Frame Operations
# ============================================================================


@tool
@idasync
def stack_frame(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Legacy stack reader (no canonical equivalent; mutation_preview only writes stack vars).
    WHEN: list stack-frame variables (name, offset, size, type) for function addresses.
    RETURNS: [{addr, vars[{name, offset, size, type}], error}] per address.
    LIMITS: non-function or frameless addresses return error entries."""
    addrs = normalize_list_input(addrs)
    results = []

    from .utils import resolve_address_or_name

    for addr in addrs:
        try:
            ea = resolve_address_or_name(addr)
            vars = get_stack_frame_variables_internal(ea, True)
            results.append({"addr": addr, "vars": vars})
        except Exception as e:
            results.append({"addr": addr, "vars": None, "error": str(e)})

    return results


@tool
@idasync
@unsafe
def declare_stack(
    items: list[StackVarDecl] | StackVarDecl,
):
    """Prefer mutation_preview(kind="declare_stack", ...).
    WHEN: create typed stack variables directly (UNSAFE; preview stages the same declare instead).
    RETURNS: [{addr, name, ok, error}] per item.
    LIMITS: function must have a frame; offset is a signed frame offset (e.g. -8), not an address."""
    items = normalize_dict_list(items)
    results = []
    for item in items:
        fn_addr = item.get("addr", "")
        offset = item.get("offset", "")
        var_name = item.get("name", "")
        type_name = item.get("ty", "")

        try:
            func = ida_funcs.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            # Frame offsets are signed (e.g. -8); they are not addresses.
            ea = int(offset, 0) if isinstance(offset, str) else int(offset)

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No frame returned"}
                )
                continue

            tif = get_type_by_name(type_name)
            if not ida_frame.define_stkvar(func, var_name, ea, tif):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "Failed to define"}
                )
                continue

            results.append({"addr": fn_addr, "name": var_name, "ok": True})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results


@tool
@idasync
@unsafe
def delete_stack(
    items: list[StackVarDelete] | StackVarDelete,
):
    """Prefer mutation_preview(kind="delete_stack", ...).
    WHEN: delete stack variables by name directly (UNSAFE; preview stages the same delete instead).
    RETURNS: [{addr, name, ok, error}] per item.
    LIMITS: special frame members and function arguments are refused with an error entry."""

    items = normalize_dict_list(items)
    results = []
    for item in items:
        fn_addr = item.get("addr", "")
        var_name = item.get("name", "")

        try:
            func = ida_funcs.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No frame returned"}
                )
                continue

            idx, udm = frame_tif.get_udm(var_name)
            if not udm:
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} not found",
                    }
                )
                continue

            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is special frame member",
                    }
                )
                continue

            udm = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(udm, tid)
            offset = udm.offset // 8
            size = udm.size // 8
            if ida_frame.is_funcarg_off(func, offset):
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is argument member",
                    }
                )
                continue

            if not ida_frame.delete_frame_members(func, offset, offset + size):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "Failed to delete"}
                )
                continue

            results.append({"addr": fn_addr, "name": var_name, "ok": True})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results
