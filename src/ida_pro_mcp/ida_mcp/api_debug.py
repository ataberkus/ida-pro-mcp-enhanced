"""Debugger operations for IDA Pro MCP.

This module provides comprehensive debugging functionality including:
- Debugger control (start, exit, continue, step, run_to)
- Breakpoint management (add, delete, enable/disable, list)
- Register inspection (all registers, GP registers, specific registers)
- Memory operations (read/write debugger memory)
- Call stack inspection
"""

import os
from typing import Annotated, TypedDict

import ida_dbg
import ida_entry
import ida_idd
import ida_idaapi
import ida_name
import idaapi

from .rpc import tool, unsafe, ext
from .sync import idasync, IDAError
from .utils import (
    RegisterValue,
    ThreadRegisters,
    Breakpoint,
    BreakpointOp,
    MemoryRead,
    MemoryPatch,
    normalize_list_input,
    normalize_dict_list,
    parse_address,
)


# ============================================================================
# Constants and Helper Functions
# ============================================================================


class DebugControlResult(TypedDict, total=False):
    ip: str
    started: bool
    continued: bool
    running: bool
    suspended: bool
    exited: bool
    state: str
    error: str


def dbg_ensure_running() -> "ida_idd.debugger_t":
    dbg = ida_idd.get_dbg()
    if not dbg:
        raise IDAError("Debugger not running")
    if ida_dbg.get_ip_val() is None:
        raise IDAError("Debugger not running")
    return dbg


def _get_process_state_name() -> str:
    if not ida_dbg.is_debugger_on():
        return "not_running"

    state = ida_dbg.get_process_state()
    if state == ida_dbg.DSTATE_SUSP:
        return "suspended"
    if state == ida_dbg.DSTATE_RUN:
        return "running"
    if state == ida_dbg.DSTATE_NOTASK:
        return "not_running"
    return f"unknown({state})"


def _get_debug_state_result() -> DebugControlResult:
    state = _get_process_state_name()
    result: DebugControlResult = {"state": state}
    if state == "running":
        result["running"] = True
    elif state == "suspended":
        result["suspended"] = True
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            result["ip"] = hex(ip)
    return result


def _get_registers_for_thread(dbg: "ida_idd.debugger_t", tid: int) -> ThreadRegisters:
    """Helper to get registers for a specific thread."""
    regs = []
    regvals: ida_idd.regvals_t = ida_dbg.get_reg_vals(tid)
    for reg_index, rv in enumerate(regvals):
        rv: ida_idd.regval_t
        reg_info = dbg.regs(reg_index)

        try:
            reg_value = rv.pyval(reg_info.dtype)
        except ValueError:
            reg_value = ida_idaapi.BADADDR

        if isinstance(reg_value, int):
            reg_value = hex(reg_value)
        if isinstance(reg_value, bytes):
            reg_value = reg_value.hex(" ")
        else:
            reg_value = str(reg_value)
        regs.append(
            RegisterValue(
                name=reg_info.name,
                value=reg_value,
            )
        )
    return ThreadRegisters(
        thread_id=tid,
        registers=regs,
    )


def _get_registers_specific_for_thread(
    dbg: "ida_idd.debugger_t", tid: int, register_names: list[str]
) -> ThreadRegisters:
    """Helper to get specific registers for a given thread."""
    all_registers = _get_registers_for_thread(dbg, tid)
    by_name = {reg["name"].upper(): reg for reg in all_registers["registers"]}
    specific_registers = []
    unknown = []
    for requested in register_names:
        key = requested.strip().upper()
        if key in by_name:
            specific_registers.append(by_name[key])
        elif requested.strip():
            unknown.append(requested.strip())
    result = ThreadRegisters(
        thread_id=tid,
        registers=specific_registers,
    )
    if unknown:
        result["unknown"] = unknown
    return result


def list_breakpoints():
    breakpoints: list[Breakpoint] = []
    for i in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            breakpoints.append(
                Breakpoint(
                    addr=hex(bpt.ea),
                    enabled=bpt.flags & ida_dbg.BPT_ENABLED,
                    condition=str(bpt.condition) if bpt.condition else None,
                )
            )
    return breakpoints


# ============================================================================
# Debugger Control Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_status() -> DebugControlResult:
    """Return debugger lifecycle state and current IP if suspended."""
    return _get_debug_state_result()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_start():
    """Start debugger session for current target.

    When no breakpoints exist, entry-point breakpoints are added automatically
    so the debugger suspends instead of running to completion. Returns
    auto_breakpoints listing any breakpoints this call added.
    """
    auto_breakpoints: list[str] = []
    if len(list_breakpoints()) == 0:
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            addr = ida_entry.get_entry(ordinal)
            if addr != ida_idaapi.BADADDR:
                ida_dbg.add_bpt(addr, 0, idaapi.BPT_SOFT)
                auto_breakpoints.append(hex(addr))

    if idaapi.start_process("", "", "") == 1:
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return {"ip": hex(ip), "auto_breakpoints": auto_breakpoints}
    raise IDAError("Failed to start debugger")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_exit():
    """Terminate active debugger session."""
    dbg_ensure_running()
    if idaapi.exit_process():
        return
    raise IDAError("Failed to exit debugger")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_detach():
    """Detach the debugger without terminating the process."""
    dbg_ensure_running()
    detach = getattr(ida_dbg, "detach_process", None) or getattr(idaapi, "detach_process", None)
    if detach is None:
        raise IDAError("Debugger backend does not support detach")
    if detach():
        return
    raise IDAError("Failed to detach debugger")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_continue() -> str:
    """Resume execution in active debugger session."""
    dbg_ensure_running()
    if idaapi.continue_process():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to continue debugger")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_run_to(
    addr: Annotated[str, "Target execution address (hex or decimal)"],
):
    """Run debuggee until target address is reached."""
    dbg_ensure_running()
    ea = parse_address(addr)
    if idaapi.run_to(ea):
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError(f"Failed to run to address {hex(ea)}")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_step_into():
    """Execute one instruction, stepping into calls."""
    dbg_ensure_running()
    if idaapi.step_into():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to step into")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_step_over():
    """Execute one instruction, stepping over calls."""
    dbg_ensure_running()
    if idaapi.step_over():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to step over")


# ============================================================================
# Breakpoint Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_bps():
    """List breakpoints with address and enabled status."""
    return list_breakpoints()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_add_bp(
    addrs: Annotated[list[str] | str, "Address(es) to add breakpoints at"],
) -> list[dict]:
    """Add breakpoints at one or more addresses."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT):
                results.append({"addr": addr, "ok": True})
            else:
                breakpoints = list_breakpoints()
                for bpt in breakpoints:
                    if bpt["addr"] == hex(ea):
                        results.append({"addr": addr, "ok": True})
                        break
                else:
                    results.append({"addr": addr, "error": "Failed to set breakpoint"})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_delete_bp(
    addrs: Annotated[list[str] | str, "Address(es) to delete breakpoints from"],
) -> list[dict]:
    """Delete breakpoints at one or more addresses."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if idaapi.del_bpt(ea):
                results.append({"addr": addr, "ok": True})
            else:
                results.append({"addr": addr, "error": "Failed to delete breakpoint"})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_toggle_bp(items: list[BreakpointOp] | BreakpointOp) -> list[dict]:
    """Enable or disable existing breakpoints in batch."""

    items = normalize_dict_list(items)

    results = []
    for item in items:
        addr = item.get("addr", "")
        enable = item.get("enabled", True)

        try:
            ea = parse_address(addr)
            if idaapi.enable_bpt(ea, enable):
                results.append({"addr": addr, "ok": True})
            else:
                results.append(
                    {
                        "addr": addr,
                        "error": f"Failed to {'enable' if enable else 'disable'} breakpoint",
                    }
                )
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


# ============================================================================
# Register Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs(
    thread: Annotated[int | None, "Thread ID (default: current thread)"] = None,
    names: Annotated[list[str] | None, "Register names to return (default: all)"] = None,
) -> ThreadRegisters:
    """Return registers for a debugger thread, optionally only the named ones."""
    dbg = dbg_ensure_running()
    if thread is None:
        thread = ida_dbg.get_current_thread()
    elif thread not in [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]:
        raise IDAError(f"Thread with ID {thread} not found")
    if names:
        return _get_registers_specific_for_thread(dbg, thread, names)
    return _get_registers_for_thread(dbg, thread)


# ============================================================================
# Call Stack Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_stacktrace() -> list[dict[str, str]]:
    """Return current call stack with module and symbol context."""
    dbg_ensure_running()
    callstack = []
    try:
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()

        if not ida_dbg.collect_stack_trace(tid, trace):
            return []
        for frame in trace:
            frame_info = {
                "addr": hex(frame.callea),
            }
            try:
                module_info = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(frame.callea, module_info):
                    frame_info["module"] = os.path.basename(module_info.name)
                else:
                    frame_info["module"] = "<unknown>"

                name = (
                    ida_name.get_nice_colored_name(
                        frame.callea,
                        ida_name.GNCN_NOCOLOR
                        | ida_name.GNCN_NOLABEL
                        | ida_name.GNCN_NOSEG
                        | ida_name.GNCN_PREFDBG,
                    )
                    or "<unnamed>"
                )
                frame_info["symbol"] = name

            except Exception:
                frame_info["module"] = "<unknown>"
                frame_info["symbol"] = "<unknown>"

            callstack.append(frame_info)

    except Exception as e:
        raise IDAError(f"Stack trace failed: {e}")
    return callstack


# ============================================================================
# Debugger Memory Operations
# ============================================================================


MAX_DBG_READ = 65536
MAX_DBG_WRITE = 65536


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_read(regions: list[MemoryRead] | MemoryRead) -> list[dict]:
    """Read debuggee memory from one or more regions."""

    regions = normalize_dict_list(regions)
    dbg_ensure_running()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["addr"])
            size = region["size"]
            if not isinstance(size, int) or size <= 0:
                results.append(
                    {"addr": region.get("addr"), "size": 0, "data": None, "error": "Size must be positive"}
                )
                continue
            if size > MAX_DBG_READ:
                results.append(
                    {"addr": region.get("addr"), "size": 0, "data": None, "error": f"Read size {size} exceeds limit {MAX_DBG_READ}"}
                )
                continue

            data = idaapi.dbg_read_memory(addr, size)
            if data:
                results.append(
                    {
                        "addr": region["addr"],
                        "size": len(data),
                        "data": data.hex(),
                        "error": None,
                    }
                )
            else:
                results.append(
                    {
                        "addr": region["addr"],
                        "size": 0,
                        "data": None,
                        "error": "Failed to read memory",
                    }
                )

        except Exception as e:
            results.append(
                {"addr": region.get("addr"), "size": 0, "data": None, "error": str(e)}
            )

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_write(regions: list[MemoryPatch] | MemoryPatch) -> list[dict]:
    """Write bytes to debuggee memory regions."""

    regions = normalize_dict_list(regions)
    dbg_ensure_running()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["addr"])
            data = bytes.fromhex(region["data"])
            if len(data) <= 0:
                results.append({"addr": region.get("addr"), "size": 0, "error": "Size must be positive"})
                continue
            if len(data) > MAX_DBG_WRITE:
                results.append({"addr": region.get("addr"), "size": 0, "error": f"Write size {len(data)} exceeds limit {MAX_DBG_WRITE}"})
                continue

            success = idaapi.dbg_write_memory(addr, data)
            results.append(
                {
                    "addr": region["addr"],
                    "size": len(data) if success else 0,
                    "ok": success,
                    "error": None if success else "Write failed",
                }
            )

        except Exception as e:
            results.append({"addr": region.get("addr"), "size": 0, "error": str(e)})

    return results
