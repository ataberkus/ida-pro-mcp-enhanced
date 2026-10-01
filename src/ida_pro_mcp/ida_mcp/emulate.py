"""Unicorn emulation of IDB code (decryptors, hash routines) without a debugger.

The IDB is snapshotted on the IDA main thread; emulation itself runs on the
caller's thread so long runs never block the UI. Imports are stubbed: a few
libc memory helpers are modelled, everything else returns 0 and is logged.
"""

from __future__ import annotations

from typing import Any

import ida_bytes
import ida_ida
import ida_nalt
import ida_name
import ida_segment
import idautils
import idc

from ida_pro_mcp.vnext.contracts import ErrorCode, VNextError

from . import compat
from .sync import IDAError, idasync

_PAGE = 0x1000
_STACK_SIZE = 0x100000
_HEAP_SIZE = 0x400000
_DEFAULT_MAX_INSNS = 2_000_000
_DEFAULT_TIMEOUT_MS = 10_000
_MAX_CALLS = 64
_MAX_WRITE_EVENTS = 200_000
_MAX_WRITE_RANGES = 64
_MAX_WRITE_BYTES = 256
_MAX_IMPORT_LOG = 100
_STRING_CAP = 256


def _align_down(value: int) -> int:
    return value & ~(_PAGE - 1)


def _align_up(value: int) -> int:
    return (value + _PAGE - 1) & ~(_PAGE - 1)


def _invalid(message: str) -> VNextError:
    return VNextError(ErrorCode.INVALID_OPERATION, message)


def _arg_value(spec: Any) -> int | bytes:
    """int/address/name -> int; {bytes|string|wstring|buffer} -> bytes placed on the scratch heap."""
    from .utils import resolve_address_or_name

    if isinstance(spec, bool):
        raise _invalid("Boolean emulation arguments are ambiguous; pass 0 or 1")
    if isinstance(spec, int):
        return spec
    if isinstance(spec, str):
        try:
            return int(spec, 0)
        except ValueError:
            try:
                return resolve_address_or_name(spec)
            except IDAError as exc:
                raise _invalid(f"Unknown emulation argument {spec!r}: {exc}") from exc
    if isinstance(spec, dict) and len(spec) == 1:
        (kind, value), = spec.items()
        try:
            if kind == "bytes":
                return bytes.fromhex(str(value).replace(" ", ""))
            if kind == "string":
                return str(value).encode("utf-8") + b"\0"
            if kind == "wstring":
                return str(value).encode("utf-16-le") + b"\0\0"
            if kind == "buffer":
                size = int(value)
                if not 0 < size <= _HEAP_SIZE // 2:
                    raise ValueError(f"buffer size must be 1..{_HEAP_SIZE // 2}")
                return b"\0" * size
        except ValueError as exc:
            raise _invalid(f"Bad {kind} emulation argument: {exc}") from exc
    raise _invalid(f"Emulation argument must be int, address/name string, or one of {{bytes|string|wstring|buffer}}: {spec!r}")


def _segment_bytes(start: int, end: int) -> bytes:
    """Segment contents with uninitialized bytes (.bss, PE virtual tails) zeroed."""
    size = end - start
    got = ida_bytes.get_bytes_and_mask(start, size)
    if not got:
        return b"\0" * size
    data, mask = got
    if all(byte == 0xFF for byte in mask):
        return bytes(data)
    out = bytearray(data)
    for index in range(size):
        if not mask[index >> 3] & (1 << (index & 7)):
            out[index] = 0
    return bytes(out)


@idasync
def _snapshot(target: str, calls: list[list[Any]]) -> dict[str, Any]:
    from .utils import resolve_address_or_name

    if ida_ida.inf_is_be():
        raise VNextError(ErrorCode.NOT_SUPPORTED, "Big-endian targets are not supported by the emulator")
    proc = ida_ida.inf_get_procname().lower()
    is64 = bool(compat.inf_is_64bit())
    if proc == "metapc":
        arch = "x64" if is64 else "x86"
    elif proc.startswith("arm"):
        arch = "arm64" if is64 else "arm"
    else:
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Emulation supports x86, x64, ARM, and ARM64, not {proc}")
    try:
        ea = resolve_address_or_name(target)
    except IDAError as exc:
        raise _invalid(str(exc)) from exc

    regions: list[tuple[int, bytes]] = []
    stub_ranges: list[tuple[int, int]] = []
    names: dict[int, str] = {}
    for seg_ea in idautils.Segments():
        seg = compat.get_segment_info(seg_ea)
        if seg is None or seg.end_ea <= seg.start_ea:
            continue
        regions.append((int(seg.start_ea), _segment_bytes(seg.start_ea, seg.end_ea)))
        if seg.get_type() == ida_segment.SEG_XTRN:
            stub_ranges.append((int(seg.start_ea), int(seg.end_ea)))
            for head in idautils.Heads(seg.start_ea, seg.end_ea):
                names[int(head)] = ida_name.get_name(head) or hex(head)

    imports: dict[int, str] = {}

    def collect(import_ea: int, name: str | None, ordinal: int) -> bool:
        imports[int(import_ea)] = name or f"ordinal_{ordinal}"
        return True

    for index in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(index, collect)
    # Delay-load IAT slots are not in the import list but carry the same __imp_ names.
    for name_ea, name in idautils.Names():
        if name.startswith("__imp_"):
            imports.setdefault(int(name_ea), name[6:])

    return {
        "ea": int(ea),
        "name": ida_name.get_name(ea) or hex(ea),
        "arch": arch,
        "windows": ida_ida.inf_get_filetype() == ida_ida.f_PE,
        "thumb": arch == "arm" and idc.get_sreg(ea, "T") == 1,
        "regions": regions,
        "stub_ranges": stub_ranges,
        "names": names,
        "imports": imports,
        "calls": [[_arg_value(arg) for arg in call] for call in calls],
    }


def _arch_spec(snap: dict[str, Any]) -> dict[str, Any]:
    import unicorn as uc
    from unicorn import arm64_const as a64
    from unicorn import arm_const as a32
    from unicorn import x86_const as x86

    arch = snap["arch"]
    if arch == "x64":
        args = [x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9]
        if not snap["windows"]:
            args = [x86.UC_X86_REG_RDI, x86.UC_X86_REG_RSI, x86.UC_X86_REG_RDX, x86.UC_X86_REG_RCX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9]
        return {"uc": (uc.UC_ARCH_X86, uc.UC_MODE_64), "ptr": 8, "sp": x86.UC_X86_REG_RSP, "pc": x86.UC_X86_REG_RIP,
                "ret": x86.UC_X86_REG_RAX, "lr": None, "args": args, "shadow": 32 if snap["windows"] else 0,
                "tls": [x86.UC_X86_REG_FS_BASE, x86.UC_X86_REG_GS_BASE]}
    if arch == "x86":
        return {"uc": (uc.UC_ARCH_X86, uc.UC_MODE_32), "ptr": 4, "sp": x86.UC_X86_REG_ESP, "pc": x86.UC_X86_REG_EIP,
                "ret": x86.UC_X86_REG_EAX, "lr": None, "args": [], "shadow": 0, "tls": []}
    if arch == "arm":
        mode = uc.UC_MODE_THUMB if snap["thumb"] else uc.UC_MODE_ARM
        return {"uc": (uc.UC_ARCH_ARM, mode), "ptr": 4, "sp": a32.UC_ARM_REG_SP, "pc": a32.UC_ARM_REG_PC,
                "ret": a32.UC_ARM_REG_R0, "lr": a32.UC_ARM_REG_LR, "shadow": 0, "tls": [],
                "args": [a32.UC_ARM_REG_R0, a32.UC_ARM_REG_R1, a32.UC_ARM_REG_R2, a32.UC_ARM_REG_R3]}
    return {"uc": (uc.UC_ARCH_ARM64, uc.UC_MODE_ARM), "ptr": 8, "sp": a64.UC_ARM64_REG_SP, "pc": a64.UC_ARM64_REG_PC,
            "ret": a64.UC_ARM64_REG_X0, "lr": a64.UC_ARM64_REG_LR, "shadow": 0, "tls": [],
            "args": [getattr(a64, f"UC_ARM64_REG_X{i}") for i in range(8)]}


def _text(data: bytes) -> str | None:
    """Printable ASCII or UTF-16LE text up to the first terminator, else None."""
    def printable(chars: bytes) -> bool:
        return len(chars) >= 2 and all(32 <= c < 127 or c in (9, 10, 13) for c in chars)

    ascii_part = data.split(b"\0", 1)[0]
    if printable(ascii_part):
        return ascii_part.decode("ascii")
    wide = data.split(b"\0\0", 1)[0]
    wide = wide + b"\0" if len(wide) % 2 else wide
    if len(wide) >= 4 and all(b == 0 for b in wide[1::2]) and printable(wide[0::2]):
        return wide[0::2].decode("ascii")
    return None


def _coalesce(events: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, size in sorted(events):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], start + size)
        else:
            merged.append([start, start + size])
    return [(start, end - start) for start, end in merged]


def _strip_import(name: str) -> str:
    if name.startswith("__imp_"):
        name = name[6:]
    if name.startswith("j_"):
        name = name[2:]
    return name.lstrip("._")


def _run_one(snap: dict[str, Any], spans: list[tuple[int, int]], arg_specs: list[int | bytes], max_insns: int, timeout_ms: int) -> dict[str, Any]:
    import unicorn as uc

    spec = _arch_spec(snap)
    ptr = spec["ptr"]
    mask = (1 << (8 * ptr)) - 1
    mu = uc.Uc(*spec["uc"])
    for start, end in spans:
        mu.mem_map(start, end - start, uc.UC_PROT_ALL)
    for start, data in snap["regions"]:
        mu.mem_write(start, data)

    base = _align_up(spans[-1][1] + 0x10000)
    stack, heap = base, base + _STACK_SIZE
    stub_page = heap + _HEAP_SIZE
    stub_size = _align_up((len(snap["imports"]) + 1) * 0x10)
    tls = stub_page + stub_size
    if tls + _PAGE > mask:
        raise VNextError(ErrorCode.NOT_SUPPORTED, "No free address space for the emulator stack/heap")
    mu.mem_map(base, tls + _PAGE - base, uc.UC_PROT_ALL)
    for reg in spec["tls"]:
        mu.reg_write(reg, tls)
    sentinel = tls - 0x10
    heap_next = [heap]

    def alloc(size: int) -> int:
        addr = heap_next[0]
        if addr + size > heap + _HEAP_SIZE:
            raise VNextError(ErrorCode.LIMIT_EXCEEDED, "Emulator heap exhausted")
        heap_next[0] = (addr + max(size, 1) + 15) & ~15
        return addr

    def pack(value: int) -> bytes:
        return (value & mask).to_bytes(ptr, "little")

    # Every import slot points into the stub page (PE IAT, delay-load, ELF data imports). Extern
    # segments are also hooked in place because ELF GOT/.plt jumps land on the extern item itself.
    names = dict(snap["names"])
    stub_ranges = list(snap["stub_ranges"])
    for index, (slot, name) in enumerate(sorted(snap["imports"].items())):
        stub = stub_page + index * 0x10
        names[stub] = name
        names.setdefault(slot, name)
        try:
            mu.mem_write(slot, pack(stub))
        except uc.UcError:
            continue
    stub_ranges.append((stub_page, sentinel))

    values = [alloc(len(arg)) if isinstance(arg, bytes) else int(arg) & mask for arg in arg_specs]
    for arg, value in zip(arg_specs, values):
        if isinstance(arg, bytes):
            mu.mem_write(value, arg)

    reg_args = spec["args"]
    stack_args = values[len(reg_args):]
    for reg, value in zip(reg_args, values):
        mu.reg_write(reg, value)
    top = stack + _STACK_SIZE - _PAGE
    if spec["lr"] is None:
        frame = ptr + spec["shadow"] + ptr * len(stack_args)
        # Entry state right after `call`: return slot at sp, sp % 16 == 16 - ptr.
        sp = ((top - frame) & ~0xF) - ptr
        mu.mem_write(sp, pack(sentinel))
        first_stack_arg = sp + ptr + spec["shadow"]
    else:
        sp = (top - ptr * len(stack_args)) & ~0xF
        mu.reg_write(spec["lr"], sentinel)
        first_stack_arg = sp
    for index, value in enumerate(stack_args):
        mu.mem_write(first_stack_arg + index * ptr, pack(value))
    mu.reg_write(spec["sp"], sp)

    def read_ptr(addr: int) -> int:
        return int.from_bytes(mu.mem_read(addr, ptr), "little")

    def call_arg(index: int) -> int:
        if index < len(reg_args):
            return mu.reg_read(reg_args[index])
        current_sp = mu.reg_read(spec["sp"])
        offset = (ptr + spec["shadow"]) if spec["lr"] is None else 0
        return read_ptr(current_sp + offset + (index - len(reg_args)) * ptr)

    def c_string_len(addr: int) -> int:
        length = 0
        while length < 0x100000 and mu.mem_read(addr + length, 1) != b"\0":
            length += 1
        return length

    def builtin(name: str) -> int:
        short = _strip_import(name)
        if short in ("malloc", "calloc"):
            size = call_arg(0) * (call_arg(1) if short == "calloc" else 1)
            return alloc(size)
        if short in ("memcpy", "memmove"):
            dst, src, size = call_arg(0), call_arg(1), call_arg(2)
            mu.mem_write(dst, bytes(mu.mem_read(src, size)))
            return dst
        if short == "memset":
            dst, byte, size = call_arg(0), call_arg(1), call_arg(2)
            mu.mem_write(dst, bytes([byte & 0xFF]) * size)
            return dst
        if short == "strlen":
            return c_string_len(call_arg(0))
        return 0

    import_log: list[dict[str, str]] = []

    def on_stub(emu, address, _size, _user):
        name = names.get(address, hex(address))
        if len(import_log) < _MAX_IMPORT_LOG:
            import_log.append({"name": name, "stubbed": "modelled" if _strip_import(name) in
                               ("malloc", "calloc", "memcpy", "memmove", "memset", "strlen") else "returned 0"})
        emu.reg_write(spec["ret"], builtin(name) & mask)
        if spec["lr"] is None:
            current_sp = emu.reg_read(spec["sp"])
            emu.reg_write(spec["sp"], current_sp + ptr)
            emu.reg_write(spec["pc"], read_ptr(current_sp))
        else:
            emu.reg_write(spec["pc"], emu.reg_read(spec["lr"]))

    for lo, hi in stub_ranges:
        mu.hook_add(uc.UC_HOOK_CODE, on_stub, begin=lo, end=hi - 1)

    write_events: list[tuple[int, int]] = []
    writes_truncated = [False]

    def on_write(_emu, _access, address, size, _value, _user):
        if len(write_events) < _MAX_WRITE_EVENTS:
            write_events.append((address, size))
        else:
            writes_truncated[0] = True

    for lo, hi in [*spans, (heap, heap + _HEAP_SIZE)]:
        mu.hook_add(uc.UC_HOOK_MEM_WRITE, on_write, begin=lo, end=hi - 1)

    begin = snap["ea"] | (1 if snap["thumb"] else 0)
    row: dict[str, Any] = {"args": [hex(value) for value in values]}
    try:
        mu.emu_start(begin, sentinel, timeout=timeout_ms * 1000, count=max_insns)
        pc = mu.reg_read(spec["pc"])
        row["status"] = "returned" if pc == sentinel else "budget_exhausted"
    except uc.UcError as exc:
        pc = mu.reg_read(spec["pc"])
        row["status"] = "fault"
        row["error"] = str(exc)
    row["pc"] = hex(pc)
    if row["status"] == "returned":
        ret = mu.reg_read(spec["ret"]) & mask
        row["return"] = hex(ret)
        try:
            text = _text(bytes(mu.mem_read(ret, _STRING_CAP)))
        except uc.UcError:
            text = None
        if text is not None:
            row["return_string"] = text
    row["imports"] = import_log
    ranges = _coalesce(write_events)
    row["writes"] = []
    for start, size in ranges[:_MAX_WRITE_RANGES]:
        data = bytes(mu.mem_read(start, min(size, _MAX_WRITE_BYTES)))
        entry: dict[str, Any] = {"addr": hex(start), "size": size, "hex": data.hex()}
        text = _text(data)
        if text is not None:
            entry["text"] = text
        row["writes"].append(entry)
    row["writes_truncated"] = writes_truncated[0] or len(ranges) > _MAX_WRITE_RANGES
    return row


def emulate(target: str, options: dict[str, Any]) -> dict[str, Any]:
    """Emulate target once per argument list in options['calls'] (default one call, no args)."""
    try:
        import unicorn  # noqa: F401
    except ImportError as exc:
        raise VNextError(
            ErrorCode.NOT_SUPPORTED,
            "Emulation needs the unicorn package in IDA's Python (pip install unicorn)",
        ) from exc
    calls = options.get("calls", [[]])
    if not isinstance(calls, list) or not all(isinstance(call, list) for call in calls):
        raise _invalid("options.calls must be a list of argument lists")
    if not 1 <= len(calls) <= _MAX_CALLS:
        raise _invalid(f"options.calls must hold 1..{_MAX_CALLS} argument lists")
    max_insns = max(1, min(int(options.get("max_insns", _DEFAULT_MAX_INSNS)), 100_000_000))
    timeout_ms = max(1, min(int(options.get("timeout_ms", _DEFAULT_TIMEOUT_MS)), 120_000))
    snap = _snapshot(target, calls)
    # ponytail: maps every segment per call; lazy page-in on UC_HOOK_MEM_UNMAPPED if huge IDBs get slow.
    spans: list[list[int]] = []
    for start, data in sorted(snap["regions"]):
        lo, hi = _align_down(start), _align_up(start + len(data))
        if spans and lo <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], hi)
        else:
            spans.append([lo, hi])
    span_tuples = [(lo, hi) for lo, hi in spans]
    return {
        "target": target,
        "addr": hex(snap["ea"]),
        "name": snap["name"],
        "arch": snap["arch"],
        "calls": [_run_one(snap, span_tuples, args, max_insns, timeout_ms) for args in snap["calls"]],
    }
