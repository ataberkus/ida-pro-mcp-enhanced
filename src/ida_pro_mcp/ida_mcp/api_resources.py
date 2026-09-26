"""MCP Resources - browsable IDB state

Resources represent browsable state (read-only data) following MCP's philosophy.
Use tools for actions that modify state or perform expensive computations.
"""

import ida_nalt
import idaapi
import idc

from .rpc import resource
from .sync import idasync
from .utils import (
    Metadata,
    get_image_size,
    hash_input_file,
)
from . import compat


# ============================================================================
# Core IDB State
# ============================================================================


@resource("ida://idb/metadata")
@idasync
def idb_metadata_resource() -> Metadata:
    """Get IDB file metadata (path, arch, base address, size, hashes)"""
    path = idc.get_idb_path()
    module = ida_nalt.get_root_filename()
    base = hex(idaapi.get_imagebase())
    size = hex(get_image_size())

    input_path = ida_nalt.get_input_file_path()
    hashed = hash_input_file(input_path)
    md5 = hashed["md5"]
    sha256 = hashed["sha256"]
    crc32 = hashed["crc32"]
    filesize = hashed["filesize"] if hashed["filesize"] == "unavailable" else hex(hashed["filesize"])

    return Metadata(
        path=path,
        module=module,
        base=base,
        size=size,
        md5=md5,
        sha256=sha256,
        crc32=crc32,
        filesize=filesize,
    )


@resource("ida://idb/entrypoints")
@idasync
def idb_entrypoints_resource() -> list[dict]:
    """Get entry points (main, TLS callbacks, etc.)"""
    entrypoints = []
    entry_count = compat.get_entry_qty()
    for i in range(entry_count):
        ordinal = compat.get_entry_ordinal(i)
        ea = compat.get_entry(ordinal)
        name = compat.get_entry_name(ordinal)
        entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
    return entrypoints


# ============================================================================
# UI State
# ============================================================================


@resource("ida://cursor")
@idasync
def cursor_resource() -> dict:
    """Get current cursor position and function"""
    import ida_kernwin

    ea = ida_kernwin.get_screen_ea()
    func = compat.get_func(ea)

    result = {"addr": hex(ea)}
    if func:
        func_name = compat.get_func_name(func)

        result["function"] = {
            "addr": hex(func.start_ea),
            "name": func_name,
        }

    return result


@resource("ida://selection")
@idasync
def selection_resource() -> dict:
    """Get current selection range (if any)"""
    import ida_kernwin

    start = ida_kernwin.read_range_selection(None)
    if start:
        return {"start": hex(start[0]), "end": hex(start[1]) if start[1] else None}
    return {"selection": None}
