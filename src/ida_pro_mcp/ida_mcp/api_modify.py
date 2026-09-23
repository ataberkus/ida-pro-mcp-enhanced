import idaapi
import idautils
import idc
import ida_hexrays
import ida_bytes
import ida_typeinf
import ida_frame
import ida_funcs
import ida_name
import ida_ua
from typing import Annotated, NotRequired, TypedDict

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import (
    parse_address,
    decompile_checked,
    refresh_decompiler_ctext,
    CommentOp,
    CommentAppendOp,
    AsmPatchOp,
    FunctionRename,
    GlobalRename,
    LocalRename,
    StackRename,
    RenameBatch,
    DefineOp,
    UndefineOp,
)


# ============================================================================
# Modification Operations
# ============================================================================

MAX_BOOKMARK_SLOTS = 1024
BOOKMARK_PREFIX = "idaMCP: "


class BookmarkResult(TypedDict, total=False):
    addr: str
    ea: str
    slot: int | None
    title: str
    prefix: str
    ok: bool
    error: str


class SetOpTypeOp(TypedDict, total=False):
    addr: str
    op_n: int
    kind: str
    struct: NotRequired[str]
    delta: NotRequired[int]
    target_addr: NotRequired[str]


class SetOpTypeResult(TypedDict, total=False):
    addr: str
    op_n: int
    kind: str
    ok: bool
    error: str


class MakeDataOp(TypedDict, total=False):
    addr: str
    type: str
    name: NotRequired[str]
    delete_existing: NotRequired[bool]


class MakeDataResult(TypedDict, total=False):
    addr: str
    name: str
    type: str
    size: int
    ok: bool
    error: str


_OP_FORMAT_FLAGS = {
    "hex": ida_bytes.FF_0NUMH,
    "dec": ida_bytes.FF_0NUMD,
    "char": ida_bytes.FF_0CHAR,
    "binary": ida_bytes.FF_0NUMB,
    "octal": ida_bytes.FF_0NUMO,
}


def _comment_batch(items, append: bool) -> list[dict]:
    if isinstance(items, dict):
        items = [items]
    if not items:
        return [{"error": "Comment batch is empty; provide addr + comment"}]

    apply = _append_comment if append else _set_comment
    results = []
    for item in items:
        addr_str = item.get("addr", "")
        comment = item.get("comment")
        if comment is None:
            comment = item.get("text", "")
        try:
            results.append({"addr": addr_str, **apply(parse_address(addr_str), comment, item)})
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})
    return results


def _set_comment(ea: int, comment: str, item: dict) -> dict:
    if not idaapi.set_cmt(ea, comment, False):
        return {"error": f"Failed to set disassembly comment at {hex(ea)}"}

    if not ida_hexrays.init_hexrays_plugin():
        return {"ok": True}

    try:
        cfunc = decompile_checked(ea)
    except IDAError:
        return {"ok": True}

    if ea == cfunc.entry_ea:
        idc.set_func_cmt(ea, comment, True)
        cfunc.refresh_func_ctext()
        return {"ok": True}

    decompiler_failed = {
        "ok": True,
        "decompiler_comment": False,
        "warning": f"Disassembly comment set; decompiler comment failed at {hex(ea)}",
    }
    eamap = cfunc.get_eamap()
    if ea not in eamap:
        return decompiler_failed

    tl = idaapi.treeloc_t()
    tl.ea = eamap[ea][0].ea
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()
        if not cfunc.has_orphan_cmts():
            return {"ok": True}
        cfunc.del_orphan_cmts()
        cfunc.save_user_cmts()
    return decompiler_failed


def _append_comment(ea: int, comment: str, item: dict) -> dict:
    scope = str(item.get("scope", "auto") or "auto").lower()
    dedupe = bool(item.get("dedupe", True))
    if scope not in {"auto", "func", "line"}:
        return {"error": f"Unsupported scope: {scope}"}

    fn = ida_funcs.get_func(ea)
    if scope == "func" or (scope == "auto" and fn is not None and fn.start_ea == ea):
        if fn is None:
            return {"error": f"No function found at {hex(ea)}"}
        current = idc.get_func_cmt(fn.start_ea, False) or ""
        new_comment, skipped = _append_comment_text(current, comment, dedupe=dedupe)
        if skipped:
            return {"ok": True, "scope": "func", "skipped": True}
        if not idc.set_func_cmt(fn.start_ea, new_comment, False):
            return {"error": f"Failed to set function comment at {hex(fn.start_ea)}"}
        return {"ok": True, "scope": "func", "appended": True}

    current = idaapi.get_cmt(ea, False) or ""
    new_comment, skipped = _append_comment_text(current, comment, dedupe=dedupe)
    if skipped:
        return {"ok": True, "scope": "line", "skipped": True}
    if not idaapi.set_cmt(ea, new_comment, False):
        return {"error": f"Failed to set disassembly comment at {hex(ea)}"}
    return {"ok": True, "scope": "line", "appended": True}


@tool
@idasync
@unsafe
def set_comments(items: list[CommentOp] | CommentOp):
    """Set comments at addresses (both disassembly and decompiler views)"""
    return _comment_batch(items, append=False)


@tool
@idasync
@unsafe
def append_comments(items: list[CommentAppendOp] | CommentAppendOp):
    """Append comments at addresses, deduping exact text by default."""
    return _comment_batch(items, append=True)


def _append_comment_text(current: str, new_text: str, *, dedupe: bool) -> tuple[str, bool]:
    normalized_new = new_text.strip()
    if dedupe and normalized_new:
        existing_entries = [line.strip() for line in current.splitlines()]
        if normalized_new in existing_entries:
            return current, True
    if not current:
        return new_text, False
    if not new_text:
        return current, False
    joiner = "" if current.endswith("\n") else "\n"
    return f"{current}{joiner}{new_text}", False


@tool
@idasync
@unsafe
def patch_asm(items: list[AsmPatchOp] | AsmPatchOp) -> list[dict]:
    """Patch assembly instructions at addresses"""
    if isinstance(items, dict):
        items = [items]

    from .api_memory import _require_mapped_range

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        instructions = item.get("asm", "")

        try:
            ea = parse_address(addr_str)
            if not str(instructions).strip():
                results.append({"addr": addr_str, "ok": False, "error": "Empty assembly"})
                continue
            statements = [part.strip() for part in instructions.split(";") if part.strip()]
            assembled = bytearray()
            assemble_error = None
            for line_index, assemble in enumerate(statements):
                try:
                    check_assemble, bytes_to_patch = idautils.Assemble(ea + len(assembled), assemble)
                    if not check_assemble:
                        assemble_error = f"Failed to assemble line {line_index} at {hex(ea)}: {assemble}"
                        break
                    assembled += bytes_to_patch
                except Exception as e:
                    assemble_error = f"Failed at line {line_index} ({hex(ea)}): {e}"
                    break
            if assemble_error:
                results.append({"addr": addr_str, "ok": False, "error": assemble_error})
                continue
            _require_mapped_range(ea, len(assembled), hex(ea))
            ida_bytes.patch_bytes(ea, bytes(assembled))
            results.append({"addr": addr_str, "ok": True})
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@tool
@idasync
@unsafe
def rename(batch: RenameBatch | dict) -> dict:
    """Batch-rename funcs/globals/locals/stack vars with dry-run options."""

    if not isinstance(batch, dict):
        return {"error": "batch must be a dict"}

    has_items = any(
        key in batch and batch.get(key) not in (None, [], {})
        for key in ("func", "data", "global", "globals", "local", "stack")
    )
    if not has_items:
        return {"error": "Rename batch is empty; provide func, data, local, or stack items"}

    stop_on_error = bool(batch.get("stop_on_error", False))
    dry_run = bool(batch.get("dry_run", False))
    allow_overwrite = bool(batch.get("allow_overwrite", False))

    def _normalize_items(items):
        if items is None:
            return []
        if isinstance(items, dict):
            return [items]
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        return []

    def _set_name_checked(ea: int, new_name: str) -> tuple[bool, str | None]:
        conflict_ea = idaapi.get_name_ea(idaapi.BADADDR, new_name)
        if (
            conflict_ea != idaapi.BADADDR
            and conflict_ea != ea
            and not allow_overwrite
        ):
            return False, f"Name already exists at {hex(conflict_ea)}"

        if dry_run:
            return True, None

        # SN_FORCE replaces a user name at this EA. Cross-EA name conflicts are
        # rejected above unless allow_overwrite is set.
        flags = idaapi.SN_CHECK | int(getattr(idaapi, "SN_FORCE", 0))
        ok = idaapi.set_name(ea, new_name, flags)
        if not ok:
            return False, "Rename failed"
        return True, None

    def _rename_funcs(items: list[FunctionRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                addr_text = item.get("addr") or item.get("func_addr") or item.get("func")
                new_name = item.get("name") or item.get("new") or item.get("new_name")
                if not addr_text or not new_name:
                    result = {
                        "addr": addr_text,
                        "name": new_name,
                        "ok": False,
                        "error": "Function rename requires addr + name",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                ea = parse_address(addr_text)
                func = ida_funcs.get_func(ea)
                if not func:
                    if ea != idaapi.BADADDR:
                        old_name = idaapi.get_name(ea) or None
                        success, error = _set_name_checked(ea, str(new_name))
                        result = {
                            "addr": addr_text,
                            "old": old_name,
                            "name": str(new_name),
                            "ok": success,
                            "error": error,
                            "dry_run": dry_run,
                        }
                        results.append(result)
                        if not success and stop_on_error:
                            halted = True
                            break
                        continue

                    result = {
                        "addr": addr_text,
                        "name": new_name,
                        "ok": False,
                        "error": "Function not found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                old_name = idaapi.get_name(func.start_ea) or None
                success, error = _set_name_checked(func.start_ea, str(new_name))
                if success and not dry_run:
                    refresh_decompiler_ctext(func.start_ea)

                result = {
                    "addr": addr_text,
                    "old": old_name,
                    "name": str(new_name),
                    "ok": success,
                    "error": error,
                    "dry_run": dry_run,
                }
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"addr": item.get("addr"), "ok": False, "error": str(e)})
                if stop_on_error:
                    halted = True
                    break
        return results, halted

    def _rename_globals(items: list[GlobalRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                addr_text = item.get("addr")
                old_name = item.get("old") or item.get("old_name")
                new_name = item.get("new") or item.get("new_name")

                # Backward-compatible forms:
                # 1) {addr, name} => rename by address
                # 2) {name, new_name} => old=name, new=new_name
                if new_name is None and addr_text is not None and item.get("name"):
                    new_name = item.get("name")
                if old_name is None and new_name is not None and item.get("name") and not addr_text:
                    old_name = item.get("name")

                if not new_name:
                    result = {
                        "old": old_name,
                        "new": None,
                        "ok": False,
                        "error": "Global rename requires target and new name",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                ea = idaapi.BADADDR
                if addr_text:
                    ea = parse_address(str(addr_text))
                    old_name = old_name or (idaapi.get_name(ea) or None)
                elif old_name:
                    ea = idaapi.get_name_ea(idaapi.BADADDR, str(old_name))

                if ea == idaapi.BADADDR:
                    result = {
                        "old": old_name,
                        "new": str(new_name),
                        "ok": False,
                        "error": f"Global '{old_name}' not found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                success, error = _set_name_checked(ea, str(new_name))
                result = {
                    "addr": hex(ea),
                    "old": old_name,
                    "new": str(new_name),
                    "ok": success,
                    "error": error,
                    "dry_run": dry_run,
                }
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"old": item.get("old"), "ok": False, "error": str(e)})
                if stop_on_error:
                    halted = True
                    break
        return results, halted

    def _rename_locals(items: list[LocalRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                func_addr = item.get("func_addr") or item.get("func")
                old_name = item.get("old") or item.get("name")
                new_name = item.get("new") or item.get("new_name")
                if not func_addr or not old_name or not new_name:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "ok": False,
                        "error": "Local rename requires func_addr + old + new",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                func = ida_funcs.get_func(parse_address(func_addr))
                if not func:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "ok": False,
                        "error": "No function found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                success = True
                error = None
                if not dry_run:
                    success = ida_hexrays.rename_lvar(func.start_ea, old_name, new_name)
                    if success:
                        refresh_decompiler_ctext(func.start_ea)
                if not success:
                    error = "Rename failed"

                result = {
                    "func_addr": func_addr,
                    "old": old_name,
                    "new": new_name,
                    "ok": success,
                    "error": error,
                    "dry_run": dry_run,
                }
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), "ok": False, "error": str(e)})
                if stop_on_error:
                    halted = True
                    break
        return results, halted

    def _rename_stack(items: list[StackRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                func_addr = item.get("func_addr") or item.get("func")
                old_name = item.get("old") or item.get("name")
                new_name = item.get("new") or item.get("new_name")
                if not func_addr or not old_name or not new_name:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "ok": False,
                        "error": "Stack rename requires func_addr + old + new",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                func = ida_funcs.get_func(parse_address(func_addr))
                if not func:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "ok": False,
                        "error": "No function found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "ok": False,
                        "error": "No frame",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                idx, udm = frame_tif.get_udm(old_name)
                if not udm:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "ok": False,
                        "error": f"'{old_name}' not found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                tid = frame_tif.get_udm_tid(idx)
                if ida_frame.is_special_frame_member(tid):
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "ok": False,
                        "error": "Special frame member",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "ok": False,
                        "error": "Argument member",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                success = True
                error = None
                if not dry_run:
                    sval = ida_frame.soff_to_fpoff(func, offset)
                    success = ida_frame.define_stkvar(func, new_name, sval, udm.type)
                if not success:
                    error = "Rename failed"

                result = {
                    "func_addr": func_addr,
                    "old": old_name,
                    "new": new_name,
                    "ok": success,
                    "error": error,
                    "dry_run": dry_run,
                }
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), "ok": False, "error": str(e)})
                if stop_on_error:
                    halted = True
                    break
        return results, halted
    data_items = []
    data_items.extend(_normalize_items(batch.get("data")))
    data_items.extend(_normalize_items(batch.get("global")))
    data_items.extend(_normalize_items(batch.get("globals")))

    requested = {
        "func": "func" in batch,
        "data": any(key in batch for key in ("data", "global", "globals")),
        "local": "local" in batch,
        "stack": "stack" in batch,
        "global_alias": any(key in batch for key in ("global", "globals")),
    }

    result: dict = {}
    stopped = False
    stopped_at = None

    if requested["func"]:
        result["func"], halted = _rename_funcs(_normalize_items(batch.get("func")))
        if halted:
            stopped = True
            stopped_at = "func"

    if requested["data"] and not stopped:
        result["data"], halted = _rename_globals(data_items)
        if requested["global_alias"]:
            result["global"] = list(result["data"])
        if halted:
            stopped = True
            stopped_at = "data"

    if requested["local"] and not stopped:
        result["local"], halted = _rename_locals(_normalize_items(batch.get("local")))
        if halted:
            stopped = True
            stopped_at = "local"

    if requested["stack"] and not stopped:
        result["stack"], halted = _rename_stack(_normalize_items(batch.get("stack")))
        if halted:
            stopped = True
            stopped_at = "stack"

    total = 0
    ok = 0
    failed = 0
    for key in ("func", "data", "local", "stack"):
        for item in result.get(key, []):
            total += 1
            if item.get("ok"):
                ok += 1
            else:
                failed += 1

    result["summary"] = {
        "total": total,
        "ok": ok,
        "failed": failed,
        "dry_run": dry_run,
        "allow_overwrite": allow_overwrite,
        "stop_on_error": stop_on_error,
        "stopped": stopped,
        "stopped_at": stopped_at,
    }
    return result


@tool
@idasync
@unsafe
def define_func(items: list[DefineOp] | DefineOp) -> list[dict]:
    """Define functions; IDA infers bounds unless end is provided."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        end_str = item.get("end", "")

        try:
            start_ea = parse_address(addr_str)
            end_ea = parse_address(end_str) if end_str else idaapi.BADADDR

            # Check if already a function
            existing = ida_funcs.get_func(start_ea)
            if existing and existing.start_ea == start_ea:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "Function already exists at this address",
                    }
                )
                continue

            success = ida_funcs.add_func(start_ea, end_ea)
            if success:
                func = ida_funcs.get_func(start_ea)
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(func.start_ea),
                        "end": hex(func.end_ea),
                        "ok": True,
                    }
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "define_func failed",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@tool
@idasync
@unsafe
def define_code(items: list[DefineOp] | DefineOp) -> list[dict]:
    """Convert bytes to code instruction(s) at address(es)."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")

        try:
            ea = parse_address(addr_str)
            length = ida_ua.create_insn(ea)
            if length > 0:
                results.append(
                    {"addr": addr_str, "ea": hex(ea), "length": length, "ok": True}
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "ea": hex(ea),
                        "error": "Failed to create instruction",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@tool
@idasync
@unsafe
def undefine(items: list[UndefineOp] | UndefineOp) -> list[dict]:
    """Undefine item(s) at address(es), converting back to raw bytes."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        end_str = item.get("end", "")
        size = item.get("size", 0)

        try:
            start_ea = parse_address(addr_str)

            # Determine size from end address or explicit size
            if end_str:
                end_ea = parse_address(end_str)
                nbytes = end_ea - start_ea
            elif size:
                nbytes = size
            else:
                # Default: undefine single item
                nbytes = 1

            success = ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, nbytes)
            if success:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "size": nbytes,
                        "ok": True,
                    }
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "undefine failed",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@tool
@idasync
@unsafe
def add_bookmark(
    addr: Annotated[str, "Address to bookmark"],
    name: Annotated[str, "Bookmark label text after the prefix"],
    prefix: Annotated[
        str,
        "Optional title prefix. Defaults to 'idaMCP: '; pass '' for no prefix.",
    ] = BOOKMARK_PREFIX,
) -> BookmarkResult:
    """Add or replace the IDA bookmark at an address. Set prefix="" for no prefix."""
    ea = parse_address(addr)
    title = f"{prefix}{name}"
    free_slot: int | None = None

    for slot in range(MAX_BOOKMARK_SLOTS):
        slot_ea = idc.get_bookmark(slot)
        if slot_ea == idc.BADADDR:
            if free_slot is None:
                free_slot = slot
            continue

        if slot_ea == ea:
            free_slot = slot
            break

    if free_slot is None:
        return {
            "addr": addr,
            "ea": hex(ea),
            "slot": None,
            "title": title,
            "prefix": prefix,
            "ok": False,
            "error": "No free bookmark slot",
        }

    idc.put_bookmark(ea, 0, 0, 0, free_slot, title)
    return {
        "addr": addr,
        "ea": hex(ea),
        "slot": free_slot,
        "title": title,
        "prefix": prefix,
        "ok": True,
    }


@tool
@idasync
@unsafe
def set_op_type(
    items: Annotated[
        list[SetOpTypeOp] | SetOpTypeOp,
        "Operand-typing ops. Equivalent to GUI 'Y' (struct offset) or 'O' (offset) operations.",
    ],
) -> list[SetOpTypeResult]:
    """Set the type of an instruction operand. GUI 'Y' / 'O' / '#' equivalent.

    `kind` values:
    - `"stroff"`: struct-offset reference. Requires `struct`, optional `delta`.
    - `"offset"`: absolute offset / pointer. Optional `target_addr`.
    - `"hex" | "dec" | "char" | "binary" | "octal"`: numeric format.
    - `"stkvar"`: stack-variable reference (function-local).
    """
    if isinstance(items, dict):
        items = [items]

    results: list[SetOpTypeResult] = []
    for item in items:
        addr_str = item.get("addr", "")
        op_n = int(item.get("op_n", 0))
        kind = str(item.get("kind", "")).strip().lower()

        try:
            ea = parse_address(addr_str)
        except Exception as e:
            results.append({"addr": addr_str, "op_n": op_n, "kind": kind, "ok": False, "error": str(e)})
            continue

        ok = False
        err = None
        try:
            if kind == "stroff":
                struct_name = str(item.get("struct", "")).strip()
                if not struct_name:
                    err = "struct name required for kind='stroff'"
                else:
                    delta = int(item.get("delta", 0))
                    til = ida_typeinf.get_idati()
                    sti = ida_typeinf.tinfo_t()
                    if not sti.get_named_type(til, struct_name):
                        err = f"struct not found: {struct_name}"
                    else:
                        tid = sti.get_tid()
                        if tid == idaapi.BADADDR:
                            err = f"struct {struct_name} has no tid"
                        else:
                            path = idaapi.tid_array(1)
                            path[0] = tid
                            ok = bool(ida_bytes.op_stroff(ea, op_n, path.cast(), 1, delta))
            elif kind == "offset":
                target_str = str(item.get("target_addr", "")).strip()
                if target_str:
                    target_ea = parse_address(target_str)
                    ok = bool(idc.op_plain_offset(ea, op_n, target_ea))
                else:
                    ok = bool(idc.op_plain_offset(ea, op_n, 0))
            elif kind == "stkvar":
                ok = bool(idc.op_stkvar(ea, op_n))
            elif kind in _OP_FORMAT_FLAGS:
                flag = _OP_FORMAT_FLAGS[kind]
                ok = bool(ida_bytes.set_op_type(ea, flag, op_n))
            else:
                err = (
                    f"unknown kind: {kind!r} "
                    "(expected stroff/offset/stkvar/hex/dec/char/binary/octal)"
                )
        except Exception as e:
            err = str(e)

        result: SetOpTypeResult = {"addr": addr_str, "op_n": op_n, "kind": kind, "ok": ok}
        if err is not None and not ok:
            result["error"] = err
        results.append(result)

    return results


@tool
@idasync
@unsafe
def make_data(
    items: Annotated[
        list[MakeDataOp] | MakeDataOp,
        "Data-creation ops. Each {addr, type, name?} replaces existing data items at addr.",
    ],
) -> list[MakeDataResult]:
    """Create a typed data symbol at an address, replacing any prior items."""
    if isinstance(items, dict):
        items = [items]

    results: list[MakeDataResult] = []
    for item in items:
        addr_str = item.get("addr", "")
        type_decl = str(item.get("type", "")).strip()
        name = str(item.get("name", "")).strip()
        delete_existing = bool(item.get("delete_existing", True))

        try:
            ea = parse_address(addr_str)
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})
            continue

        if not type_decl:
            results.append({"addr": addr_str, "ok": False, "error": "type declaration is required"})
            continue

        decl = type_decl if type_decl.endswith(";") else type_decl + ";"

        try:
            tif = ida_typeinf.tinfo_t()
            parsed = ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL)
            badsize = getattr(idaapi, "BADSIZE", idaapi.BADADDR)
            size = tif.get_size() if parsed is not None else 0
            if parsed is None or size in (0, badsize):
                results.append(
                    {
                        "addr": addr_str,
                        "ok": False,
                        "error": f"Could not parse declaration: {decl!r}",
                    }
                )
                continue

            if delete_existing:
                ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, size)
            apply_ok = idc.SetType(ea, decl)
            if not apply_ok:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": False,
                        "error": f"SetType rejected declaration: {decl!r}",
                    }
                )
                continue

            if name:
                ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)

            ida_hexrays.clear_cached_cfuncs()

            results.append(
                {
                    "addr": addr_str,
                    "name": name or (ida_name.get_name(ea) or ""),
                    "type": idc.get_type(ea) or "",
                    "size": size,
                    "ok": True,
                }
            )
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    return results
