import fnmatch
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from typing import (
    Annotated,
    Any,
    Callable,
    Generic,
    Literal,
    NotRequired,
    Optional,
    TypedDict,
    TypeVar,
    overload,
)

import ida_funcs
import ida_hexrays
import ida_idp
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc

from . import compat
from .sync import IDAError

# ============================================================================
# TypedDict Definitions for API Parameters
# ============================================================================


class MemoryRead(TypedDict):
    """Memory read request"""

    addr: Annotated[str, "Address to read from (hex or decimal)"]
    size: Annotated[int, "Number of bytes to read"]


class MemoryPatch(TypedDict):
    """Memory patch operation"""

    addr: Annotated[str, "Address to patch (hex or decimal)"]
    data: Annotated[str, "Hex data to write (space-separated bytes)"]


class IntRead(TypedDict):
    """Integer read request"""

    addr: Annotated[str, "Address to read from (hex or decimal)"]
    ty: Annotated[str, "Integer class (u8/u32/uint32/i16le/u64be/etc)"]


class IntWrite(TypedDict):
    """Integer write request"""

    addr: Annotated[str, "Address to write to (hex or decimal)"]
    ty: Annotated[str, "Integer class (u8/u32/uint32/i16le/u64be/etc)"]
    value: Annotated[
        str,
        "Integer value as string (decimal or 0x..; negatives allowed for signed)",
    ]


class CommentOp(TypedDict):
    """Comment operation"""

    addr: Annotated[str, "Address (hex or decimal)"]
    comment: Annotated[str, "Comment text"]


class CommentAppendOp(TypedDict, total=False):
    """Comment append operation"""

    addr: Annotated[str, "Address (hex or decimal)"]
    comment: Annotated[str, "Comment text to append"]
    scope: Annotated[str, "auto|func|line (default: auto)"]
    dedupe: Annotated[bool, "Skip if exact text already exists (default: true)"]


class AsmPatchOp(TypedDict):
    """Assembly patch operation"""

    addr: Annotated[str, "Address (hex or decimal)"]
    asm: Annotated[str, "Assembly instruction(s), semicolon-separated"]


class FunctionRename(TypedDict):
    """Function rename operation"""

    addr: Annotated[str, "Function address (hex or decimal)"]
    name: Annotated[str, "New function name"]


class GlobalRename(TypedDict):
    """Global variable rename operation"""

    old: Annotated[str, "Current variable name"]
    new: Annotated[str, "New variable name"]


class LocalRename(TypedDict):
    """Local variable rename operation"""

    func_addr: Annotated[str, "Function address containing the local variable"]
    old: Annotated[str, "Current variable name"]
    new: Annotated[str, "New variable name"]


class StackRename(TypedDict):
    """Stack variable rename operation"""

    func_addr: Annotated[str, "Function address containing the stack variable"]
    old: Annotated[str, "Current variable name"]
    new: Annotated[str, "New variable name"]


class RenameBatch(TypedDict, total=False):
    """Batch rename operations across all entity types"""

    func: Annotated[
        list[FunctionRename] | FunctionRename | None, "Function rename operations"
    ]
    data: Annotated[
        list[GlobalRename] | GlobalRename | None,
        "Global/data variable rename operations",
    ]
    local: Annotated[
        list[LocalRename] | LocalRename | None, "Local variable rename operations"
    ]
    stack: Annotated[
        list[StackRename] | StackRename | None, "Stack variable rename operations"
    ]
    stop_on_error: Annotated[bool, "Stop processing remaining items on first failure"]
    dry_run: Annotated[bool, "Validate only; report what would change"]
    allow_overwrite: Annotated[
        bool,
        "Allow renaming even if target name already exists when backend supports force mode",
    ]


class StructFieldQuery(TypedDict):
    """Struct field query for xrefs"""

    struct: Annotated[str, "Structure name"]
    field: Annotated[str, "Field name"]


class XrefQuery(TypedDict, total=False):
    """Generic cross-reference query"""

    query: Annotated[str, "Address or name to resolve"]
    direction: Annotated[str, "to|from|both (default: both)"]
    xref_type: Annotated[str, "any|code|data (default: any)"]
    offset: Annotated[int, "Starting index (default: 0)"]
    count: Annotated[int, "Maximum results (default: 200, max: 5000)"]
    include_fn: Annotated[bool, "Include function metadata when available"]
    dedup: Annotated[bool, "Deduplicate by address/type (default: true)"]
    sort_by: Annotated[str, "Sort key: addr|type (default: addr)"]
    descending: Annotated[bool, "Sort descending (default: false)"]


class ListQuery(TypedDict, total=False):
    """Pagination query for listing operations"""

    filter: Annotated[str, "Optional glob pattern to filter results"]
    offset: Annotated[int, "Starting index (default: 0)"]
    count: Annotated[int, "Maximum number of results (default: 50, 0 for all)"]


class EntityQuery(TypedDict, total=False):
    """Generic IDB entity query with filtering, projection, and pagination"""

    kind: Annotated[
        Literal["functions", "globals", "imports", "strings", "names", "switches", "patches", "classes", "vtables", "signatures", "type_libraries"],
        "Entity kind: functions|globals|imports|strings|names|switches|patches|classes|vtables|signatures|type_libraries",
    ]
    filter: Annotated[str, "Optional glob/regex filter (name/text depending on kind)"]
    regex: Annotated[str, "Optional regex applied to the primary text field"]
    min_addr: Annotated[str, "Optional minimum address bound (hex/decimal)"]
    max_addr: Annotated[str, "Optional maximum address bound (hex/decimal)"]
    segment: Annotated[str, "Optional segment filter for address-backed entities"]
    module: Annotated[str, "Optional import module filter (imports only)"]
    offset: Annotated[int, "Starting index (default: 0)"]
    count: Annotated[int, "Maximum number of results (default: 100, 0 for all)"]
    sort_by: Annotated[str, "Sort key, e.g. addr|name|size|length"]
    descending: Annotated[bool, "Sort descending (default: false)"]
    fields: Annotated[
        list[str] | str,
        "Optional projection list; only selected fields are returned",
    ]
    case_sensitive: Annotated[
        NotRequired[bool], "Case-sensitive regex match (default: true)"
    ]
    targets: Annotated[
        NotRequired[list[str]],
        "Optional switch-target scope: function names/addresses (switches only)",
    ]


class FuncProfileQuery(TypedDict, total=False):
    """Function profiling query with pagination and optional detail lists"""

    query: Annotated[str, "Address/name or '*' for all functions"]
    filter: Annotated[str, "Optional function-name glob/regex filter"]
    offset: Annotated[int, "Starting index (default: 0)"]
    count: Annotated[int, "Maximum number of results (default: 50, 0 for all)"]
    sort_by: Annotated[str, "Sort key: addr|name|size (default: addr)"]
    descending: Annotated[bool, "Sort descending (default: false)"]
    include_lists: Annotated[bool, "Include sampled callers/callees/strings/constants"]
    max_items: Annotated[int, "Max sampled items per list when include_lists=true"]
    include_prototype: Annotated[bool, "Include recovered function prototype text"]


class AnalyzeBatchQuery(TypedDict, total=False):
    """Comprehensive function analysis request"""

    query: Annotated[str, "Function address or name"]
    include_decompile: Annotated[bool, "Include decompiler output (default: true)"]
    include_disasm: Annotated[
        bool, "Include disassembly lines (default: false, use max_disasm_insns)"
    ]
    include_xrefs: Annotated[bool, "Include xrefs-to/from summary (default: true)"]
    include_callers: Annotated[bool, "Include caller list (default: true)"]
    include_callees: Annotated[bool, "Include callee list (default: true)"]
    include_strings: Annotated[bool, "Include referenced strings (default: true)"]
    include_constants: Annotated[
        bool, "Include immediate constants referenced in function (default: true)"
    ]
    include_basic_blocks: Annotated[
        bool, "Include CFG basic blocks (default: true, capped by max_blocks)"
    ]
    include_proto: Annotated[bool, "Include recovered prototype (default: true)"]
    max_disasm_insns: Annotated[
        int, "Maximum disassembly instructions when include_disasm=true (default: 300)"
    ]
    max_callers: Annotated[int, "Maximum callers returned (default: 100)"]
    max_callees: Annotated[int, "Maximum callees returned (default: 100)"]
    max_strings: Annotated[int, "Maximum string refs returned (default: 100)"]
    max_constants: Annotated[int, "Maximum constants returned (default: 200)"]
    max_blocks: Annotated[int, "Maximum basic blocks returned (default: 500)"]


class ImportQuery(TypedDict, total=False):
    """Import query with filtering and pagination"""

    filter: Annotated[str, "Optional import name glob/regex filter"]
    module: Annotated[str, "Optional module name glob/regex filter"]
    offset: Annotated[int, "Starting index (default: 0)"]
    count: Annotated[int, "Maximum number of results (default: 100, 0 for all)"]


class TypeInspectQuery(TypedDict, total=False):
    """Type inspection request"""

    name: Annotated[str, "Type name"]
    include_members: Annotated[bool, "Include member details for UDT types"]
    max_members: Annotated[int, "Maximum members to include (default: 128)"]


class TypeQuery(TypedDict, total=False):
    """Type catalog query with filtering, pagination, and optional relationships"""

    filter: Annotated[str, "Optional type name glob/regex filter"]
    kind: Annotated[
        Literal["any", "struct", "union", "enum", "typedef", "func", "ptr", "udt"],
        "any|struct|union|enum|typedef|func|ptr|udt (default: any)",
    ]
    offset: Annotated[int, "Starting index (default: 0)"]
    count: Annotated[int, "Maximum results (default: 100, 0 for all)"]
    sort_by: Annotated[str, "Sort key: name|size|ordinal (default: name)"]
    descending: Annotated[bool, "Sort descending (default: false)"]
    include_decl: Annotated[bool, "Include declaration text (default: true)"]
    include_members: Annotated[bool, "Include UDT member details (default: false)"]
    max_members: Annotated[int, "Maximum members per UDT (default: 64)"]
    include_relationships: Annotated[
        bool,
        "Include related/member type names to support type navigation (default: false)",
    ]


class BreakpointOp(TypedDict):
    """Debugger breakpoint operation"""

    addr: Annotated[str, "Breakpoint address (hex or decimal)"]
    enabled: Annotated[bool, "Enable (true) or disable (false)"]


class InsnPattern(TypedDict, total=False):
    """Instruction pattern for operand search"""

    mnem: Annotated[str, "Instruction mnemonic to match"]
    op0: Annotated[int, "Value to match in first operand"]
    op1: Annotated[int, "Value to match in second operand"]
    op2: Annotated[int, "Value to match in third operand"]
    op_any: Annotated[int, "Value to match in any operand"]
    func: Annotated[str, "Function address to scope the scan"]
    segment: Annotated[str, "Segment name to scope the scan"]
    start: Annotated[str, "Start address (hex/dec) to scope the scan"]
    end: Annotated[str, "End address (hex/dec, exclusive) to scope the scan"]
    offset: Annotated[int, "Starting match index (default: 0)"]
    count: Annotated[int, "Maximum matches to return (default: 100, max: 5000)"]
    max_scan_insns: Annotated[
        int, "Max instructions to scan (default: 200000, max: 2000000)"
    ]
    include_fn: Annotated[
        bool, "Include containing function metadata for each match (default: false)"
    ]
    include_disasm: Annotated[
        bool, "Include disassembly text for each match (default: false)"
    ]
    allow_broad: Annotated[
        bool,
        "Allow scans without scope (default: false). Use with care on large binaries.",
    ]


class NumberConversion(TypedDict, total=False):
    """Number conversion request"""

    text: Annotated[str, "Number string to convert"]
    size: Annotated[int, "Byte size for conversion (omit for auto)"]


class StructRead(TypedDict, total=False):
    """Structure read request

    Address is required. Struct name is optional - if omitted, will attempt
    to auto-detect from type information already applied at the address.
    """

    addr: Annotated[str, "Memory address (hex or decimal)"]
    struct: Annotated[
        NotRequired[str], "Structure name (optional, auto-detect if omitted)"
    ]


class TypeEdit(TypedDict, total=False):
    """Type application operation"""

    addr: Annotated[str, "Memory address"]
    name: Annotated[str, "Variable/function name"]
    ty: Annotated[str, "Type name or declaration"]
    kind: Annotated[str, "Type of entity (auto-detected if omitted)"]
    signature: Annotated[str, "Function signature (for kind=function)"]
    variable: Annotated[str, "Local variable name (for kind=local)"]


class EnumMemberUpsert(TypedDict, total=False):
    """Enum member upsert operation"""

    name: Annotated[str, "Enum member name"]
    value: Annotated[int | str, "Enum member value"]


class EnumUpsert(TypedDict, total=False):
    """Enum create/update operation"""

    name: Annotated[str, "Enum type name"]
    members: Annotated[list[EnumMemberUpsert] | EnumMemberUpsert, "Members to upsert"]
    bitfield: Annotated[bool, "Whether the enum is a bitfield (default: false)"]


class StackVarDecl(TypedDict):
    """Stack variable declaration"""

    addr: Annotated[str, "Function address"]
    offset: Annotated[str, "Stack offset"]
    name: Annotated[str, "Variable name"]
    ty: Annotated[str, "Type name"]


class StackVarDelete(TypedDict):
    """Stack variable deletion"""

    addr: Annotated[str, "Function address"]
    name: Annotated[str, "Variable name"]


class DefineOp(TypedDict, total=False):
    """Define function/code operation"""

    addr: Annotated[
        str, "Address to define (hex or decimal). Use 'start:end' for explicit bounds."
    ]
    end: Annotated[str, "Optional end address for explicit bounds"]


class UndefineOp(TypedDict, total=False):
    """Undefine operation"""

    addr: Annotated[str, "Address to undefine (hex or decimal)"]
    end: Annotated[str, "Optional end address"]
    size: Annotated[int, "Optional size in bytes"]


# ============================================================================
# TypedDict Definitions for Results
# ============================================================================


class Metadata(TypedDict):
    path: str
    module: str
    base: str
    size: str
    md5: str
    sha256: str
    crc32: str
    filesize: str


class Function(TypedDict):
    addr: str
    name: str
    size: str


class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str


class Global(TypedDict):
    addr: str
    name: str


class Import(TypedDict):
    addr: str
    imported_name: str
    module: str


class String(TypedDict):
    addr: str
    length: int
    string: str


class DisassemblyLine(TypedDict):
    segment: NotRequired[str]
    addr: str
    label: NotRequired[str]
    instruction: str
    comments: NotRequired[list[str]]


class Argument(TypedDict):
    name: str
    type: str


class StackFrameVariable(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class DisassemblyFunction(TypedDict):
    name: str
    start_ea: str
    return_type: NotRequired[str]
    arguments: NotRequired[list[Argument]]
    stack_frame: list[StackFrameVariable]
    lines: list[DisassemblyLine]


class Xref(TypedDict):
    addr: str
    type: str
    fn: Optional[Function]


class RegisterValue(TypedDict):
    name: str
    value: str


class ThreadRegisters(TypedDict):
    thread_id: int
    registers: list[RegisterValue]
    unknown: NotRequired[list[str]]


class Breakpoint(TypedDict):
    addr: str
    enabled: bool
    condition: Optional[str]


class FunctionAnalysis(TypedDict):
    addr: str
    name: Optional[str]
    code: Optional[str]
    asm: Optional[str]
    xto: list[Xref]
    xfrom: list[Xref]
    callees: list[dict]
    callers: list[Function]
    strings: list[String]
    constants: list[dict]
    blocks: list[dict]
    error: Optional[str]
    prompt: Optional[str]


class PatternMatch(TypedDict):
    pattern: str
    matches: list[str]
    count: int


class CodePattern(TypedDict):
    mnemonic: str
    operands: NotRequired[list[str]]


class BasicBlock(TypedDict):
    start: str
    end: str
    size: int
    type: int
    successors: list[str]
    predecessors: list[str]


T = TypeVar("T")


class Page(TypedDict, Generic[T]):
    data: list[T]
    next_offset: Optional[int]


# ============================================================================
# Helper Functions
# ============================================================================


def get_image_size() -> int:
    from . import compat

    omin_ea = compat.inf_get_omin_ea()
    omax_ea = compat.inf_get_omax_ea()

    image_size = omax_ea - omin_ea
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size


def parse_address(addr: str | int) -> int:
    if addr is None or (isinstance(addr, str) and not addr.strip()):
        raise IDAError("Failed to parse address: empty address")
    if isinstance(addr, bool):
        raise IDAError("Failed to parse address: invalid bool address")
    if isinstance(addr, int):
        if addr < 0:
            raise IDAError(f"Failed to parse address: negative address {addr!r}")
        if addr > 0xFFFFFFFFFFFFFFFF:
            raise IDAError(f"Failed to parse address: out of range {addr!r}")
        return addr
    try:
        return int(addr, 0)
    except (TypeError, ValueError):
        text = str(addr)
        # Tool docs promise "address or name"; resolve IDA symbols before failing.
        try:
            ea = idaapi.get_name_ea(idaapi.BADADDR, text.strip())
        except Exception:
            ea = idaapi.BADADDR
        if ea != idaapi.BADADDR:
            return int(ea)
        for ch in text:
            if ch not in "0123456789abcdefABCDEF":
                raise IDAError(f"Failed to parse address: {addr}")
        raise IDAError(f"Failed to parse address (missing 0x prefix): {addr}")


def normalize_list_input(value: list | str) -> list:
    """Normalize input to list - accepts list or comma-separated string"""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]


def normalize_dict_list(
    value: list[dict] | dict | str | list[str] | Any,
    string_parser: Optional[Callable[[str], dict]] = None,
) -> list[dict]:
    """Normalize input to list[dict] with optional string parsing

    Args:
        value: Input value (dict, list[dict], str, list[str], or any)
        string_parser: Optional function to convert string → dict
                      If None, strings → empty dict

    Flow:
        dict → [dict]
        str → split by ',' → list[str] → map(string_parser) → list[dict]
        list[str] → map(string_parser) → list[dict]
        list[dict] → list[dict]
        Any → [{}]
    """
    if isinstance(value, dict):
        return [value]
    elif isinstance(value, list):
        return _normalize_parsed_list(value, string_parser)
    elif isinstance(value, str):
        # Try JSON parse first
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return [parsed]
            elif isinstance(parsed, list):
                return _normalize_parsed_list(parsed, string_parser)
        except (json.JSONDecodeError, ValueError):
            pass

        # Not JSON - split by comma and parse
        parts = [s.strip() for s in value.split(",") if s.strip()]
        if not parts:
            return [{}]

        if string_parser:
            return [string_parser(part) for part in parts]
        return [{}]
    else:
        # Any other type → empty dict
        return [{}]


def _normalize_parsed_list(value: list, string_parser=None) -> list[dict]:
    if not value:
        return [{}]
    if all(isinstance(item, dict) for item in value):
        return value
    if all(isinstance(item, str) for item in value):
        if string_parser:
            return [string_parser(s.strip()) for s in value if s.strip()]
        return []
    return [item for item in value if isinstance(item, dict)] or [{}]


def clamp_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        i = int(value)  # type: ignore[arg-type]
    except Exception:
        i = default
    if i < minimum:
        return minimum
    if i > maximum:
        return maximum
    return i


def resolve_address_or_name(addr: str | int) -> int:
    """Resolve an int, hex string, or IDA symbol name to an ea."""
    import idaapi

    if isinstance(addr, int) and not isinstance(addr, bool):
        return parse_address(addr)
    s = str(addr)
    if s.startswith("0x") or s.startswith("0X"):
        return parse_address(s)
    ea = idaapi.get_name_ea(idaapi.BADADDR, s)
    if ea != idaapi.BADADDR:
        return int(ea)
    return parse_address(s)


def hash_input_file(path: str, *, chunk_size: int = 1 << 20) -> dict:
    """Hash a file in chunks. All values are "unavailable" on OSError."""
    try:
        size = os.path.getsize(path)
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        crc = 0
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)
                crc = zlib.crc32(chunk, crc)
        return {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest(),
            "crc32": hex(crc & 0xFFFFFFFF),
            "filesize": size,
        }
    except OSError:
        return {"md5": "unavailable", "sha256": "unavailable", "crc32": "unavailable", "filesize": "unavailable"}


@overload
def get_function(addr: int, *, raise_error: Literal[True]) -> Function: ...


@overload
def get_function(addr: int) -> Function: ...


@overload
def get_function(addr: int, *, raise_error: Literal[False]) -> Optional[Function]: ...


def get_function(addr, *, raise_error=True):
    from . import compat

    fn = compat.get_func(addr)
    if fn is None:
        if raise_error:
            raise IDAError(f"No function found at address {hex(addr)}")
        return None

    name = compat.get_func_name(fn)
    end_ea = compat.get_func_end_ea(fn)

    return Function(addr=hex(fn.start_ea), name=name, size=hex(end_ea - fn.start_ea))


def get_prototype(fn: ida_funcs.func_t) -> Optional[str]:
    from . import compat

    prototype = compat.get_func_prototype(fn)
    if prototype is not None:
        return str(prototype)

    # Fallback: try idc.get_type
    try:
        return idc.get_type(fn.start_ea)
    except Exception:
        pass

    return None


def get_type_by_name(type_name: str) -> ida_typeinf.tinfo_t:
    # 8-bit integers
    if type_name in ("int8", "__int8", "int8_t", "char", "signed char"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT8)
    elif type_name in ("uint8", "__uint8", "uint8_t", "unsigned char", "byte", "BYTE"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT8)
    # 16-bit integers
    elif type_name in (
        "int16",
        "__int16",
        "int16_t",
        "short",
        "short int",
        "signed short",
        "signed short int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT16)
    elif type_name in (
        "uint16",
        "__uint16",
        "uint16_t",
        "unsigned short",
        "unsigned short int",
        "word",
        "WORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT16)
    # 32-bit integers
    elif type_name in (
        "int32",
        "__int32",
        "int32_t",
        "int",
        "signed int",
        "long",
        "long int",
        "signed long",
        "signed long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
    elif type_name in (
        "uint32",
        "__uint32",
        "uint32_t",
        "unsigned int",
        "unsigned long",
        "unsigned long int",
        "dword",
        "DWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT32)
    # 64-bit integers
    elif type_name in (
        "int64",
        "__int64",
        "int64_t",
        "long long",
        "long long int",
        "signed long long",
        "signed long long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT64)
    elif type_name in (
        "uint64",
        "__uint64",
        "uint64_t",
        "unsigned int64",
        "unsigned long long",
        "unsigned long long int",
        "qword",
        "QWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT64)
    # 128-bit integers
    elif type_name in ("int128", "__int128", "int128_t", "__int128_t"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT128)
    elif type_name in (
        "uint128",
        "__uint128",
        "uint128_t",
        "__uint128_t",
        "unsigned int128",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT128)
    # Floating point types
    elif type_name in ("float",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_FLOAT)
    elif type_name in ("double",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_DOUBLE)
    elif type_name in ("long double", "ldouble"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_LDOUBLE)
    # Boolean type
    elif type_name in ("bool", "_Bool", "boolean"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_BOOL)
    # Void type
    elif type_name in ("void",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
    # Named types
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_STRUCT):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_TYPEDEF):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_ENUM):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_UNION):
        return tif
    if tif := ida_typeinf.tinfo_t(type_name):
        return tif

    raise IDAError(f"Unable to retrieve {type_name} type info object")


def paginate(data: list[T], offset: int, count: int) -> Page[T]:
    offset = clamp_int(offset, 0, 0, 2_000_000_000)
    count = clamp_int(count, 0, 0, 5000)
    if count == 0:
        count = len(data)
    if offset >= len(data):
        return {"data": [], "next_offset": None}
    next_offset = offset + count
    if next_offset >= len(data):
        next_offset = None
    return {
        "data": data[offset : offset + count],
        "next_offset": next_offset,
    }


def pattern_filter(data: list[T], pattern: str, key: str) -> list[T]:
    if not pattern:
        return data

    regex = None
    use_glob = False

    # Regex pattern: /pattern/flags
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash = pattern.rfind("/")
        body = pattern[1:last_slash]
        flag_str = pattern[last_slash + 1 :]

        flags = 0
        for ch in flag_str:
            if ch == "i":
                flags |= re.IGNORECASE
            elif ch == "m":
                flags |= re.MULTILINE
            elif ch == "s":
                flags |= re.DOTALL

        try:
            regex = re.compile(body, flags or re.IGNORECASE)
        except re.error:
            regex = None
    # Glob pattern: contains * or ?
    elif "*" in pattern or "?" in pattern:
        use_glob = True

    def get_value(item) -> str:
        try:
            v = item[key]
        except Exception:
            v = getattr(item, key, "")
        return "" if v is None else str(v)

    def matches(item) -> bool:
        text = get_value(item)
        if regex is not None:
            return bool(regex.search(text))
        if use_glob:
            return fnmatch.fnmatch(text.lower(), pattern.lower())
        return pattern.lower() in text.lower()

    return [item for item in data if matches(item)]


def refresh_decompiler_ctext(fn_addr: int):
    if not ida_hexrays.init_hexrays_plugin():
        return
    error = ida_hexrays.hexrays_failure_t()
    decompile_function = getattr(ida_hexrays, "decompile_function", None)
    if decompile_function is None:
        decompile_function = ida_hexrays.decompile_func
    cfunc: ida_hexrays.cfunc_t = decompile_function(
        fn_addr, error, ida_hexrays.DECOMP_WARNINGS
    )
    if cfunc:
        cfunc.refresh_func_ctext()


class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvinf):
        for lvar_saved in lvinf.lvvec:
            lvar_saved: ida_hexrays.lvar_saved_info_t
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False


def parse_decls_ctypes(decls: str, hti_flags: int) -> tuple[int, list[str]]:
    if sys.platform == "win32":
        import ctypes

        assert isinstance(decls, str), "decls must be a string"
        assert isinstance(hti_flags, int), "hti_flags must be an int"
        c_decls = decls.encode("utf-8")
        c_til = None
        ida_dll = ctypes.CDLL("ida")
        ida_dll.parse_decls.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        ida_dll.parse_decls.restype = ctypes.c_int

        messages: list[str] = []

        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
        def magic_printer(fmt: bytes, arg1: bytes):
            if fmt.count(b"%") == 1 and b"%s" in fmt:
                formatted = fmt.replace(b"%s", arg1)
                messages.append(formatted.decode("utf-8"))
                return len(formatted) + 1
            else:
                messages.append(f"unsupported magic_printer fmt: {repr(fmt)}")
                return 0

        errors = ida_dll.parse_decls(c_til, c_decls, magic_printer, hti_flags)
    else:
        errors = ida_typeinf.parse_decls(None, decls, False, hti_flags)
        messages = []
    return errors, messages


def get_stack_frame_variables_internal(
    fn_addr: int, raise_error: bool
) -> list[StackFrameVariable]:
    from . import compat
    from .sync import ida_major

    if ida_major < 9:
        return []

    func = compat.get_func(fn_addr)
    if not func:
        if raise_error:
            raise IDAError(f"No function found at address {fn_addr:#x}")
        return []

    frame_id = (
        func.get_frame_id() if hasattr(func, "get_frame_id") else getattr(func, "frame", None)
    )
    if frame_id is None:
        return []

    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(frame_id) or not tif.is_udt():
        return []

    members: list[StackFrameVariable] = []
    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    for udm in udt:
        if not udm.is_gap():
            name = udm.name
            offset = udm.offset // 8
            size = udm.size // 8
            type = str(udm.type)
            members.append(
                StackFrameVariable(
                    name=name, offset=hex(offset), size=hex(size), type=type
                )
            )
    return members


class DecompilationError(IDAError):
    """Hex-Rays failure with machine-readable diagnostic details."""

    def __init__(self, message: str, details: dict[str, Any]):
        super().__init__(message)
        self.details = details


def _hexrays_failure_details(addr: int, failure) -> dict[str, Any]:
    try:
        code = int(failure.code)
    except Exception:
        code = None
    code_name = None
    if code is not None:
        for name in dir(ida_hexrays):
            if not name.startswith("MERR_"):
                continue
            try:
                if int(getattr(ida_hexrays, name)) == code:
                    code_name = name
                    break
            except Exception:
                continue
    try:
        description = str(failure.desc() or "")
    except Exception:
        description = ""
    try:
        detail = str(failure.str or "")
    except Exception:
        detail = ""
    try:
        error_address = int(failure.errea)
    except Exception:
        error_address = idaapi.BADADDR

    return {
        "resolved_addr": hex(addr),
        "hexrays_code": code,
        "hexrays_code_name": code_name,
        "hexrays_description": description or None,
        "hexrays_detail": detail or None,
        "failure_addr": (
            None if error_address == idaapi.BADADDR else hex(error_address)
        ),
    }


def decompile_checked(addr: int):
    """Decompile a function and raise a detailed error on failure (uses cache)."""
    if not ida_hexrays.init_hexrays_plugin():
        raise DecompilationError(
            "Hex-Rays decompiler is not available",
            {
                "resolved_addr": hex(addr),
                "reason": "decompiler_unavailable",
            },
        )
    failure = ida_hexrays.hexrays_failure_t()
    decompile_function = getattr(ida_hexrays, "decompile_function", None)
    try:
        if decompile_function is None:
            cfunc = ida_hexrays.decompile(addr, failure)
        else:
            cfunc = decompile_function(addr, failure)
    except Exception as exc:
        raise DecompilationError(
            f"Hex-Rays raised {type(exc).__name__} while decompiling {hex(addr)}: {exc}",
            {
                "resolved_addr": hex(addr),
                "reason": "decompiler_exception",
                "exception_type": type(exc).__name__,
                "exception": str(exc),
            },
        ) from exc
    if not cfunc:
        details = _hexrays_failure_details(addr, failure)
        if failure.code == ida_hexrays.MERR_LICENSE:
            details["reason"] = "license_unavailable"
            raise DecompilationError(
                "Decompiler license is not available; use `disassemble` for assembly instead",
                details,
            )

        details["reason"] = "hexrays_failure"
        explanation = details.get("hexrays_detail") or details.get(
            "hexrays_description"
        )
        message = f"Decompilation failed at {hex(addr)}"
        if explanation:
            message += f": {explanation}"
        if details.get("failure_addr"):
            message += f" (failure address: {details['failure_addr']})"
        if details.get("hexrays_code_name"):
            message += f" [{details['hexrays_code_name']}]"
        raise DecompilationError(message, details)
    return cfunc


def _render_decompiled_function(cfunc) -> str:
    import ida_lines
    import ida_kernwin

    sv = cfunc.get_pseudocode()
    lines = []
    for sl in sv:
        sl: ida_kernwin.simpleline_t
        item = ida_hexrays.ctree_item_t()
        line_ea = None
        if cfunc.get_line_item(sl.line, 0, False, None, item, None):
            dstr: str | None = item.dstr()
            if dstr:
                ds = dstr.split(": ")
                if len(ds) == 2:
                    try:
                        line_ea = int(ds[0], 16)
                    except ValueError:
                        pass
        text = ida_lines.tag_remove(sl.line)
        if line_ea is not None:
            lines.append(f"{text} /*{line_ea:#x}*/")
        else:
            lines.append(text)
    return "\n".join(lines)


def decompile_function_detailed(ea: int) -> str:
    """Decompile and render pseudocode, preserving the exact failure reason."""
    cfunc = decompile_checked(ea)
    try:
        return _render_decompiled_function(cfunc)
    except Exception as exc:
        raise DecompilationError(
            f"Pseudocode rendering failed at {hex(ea)}: {exc}",
            {
                "resolved_addr": hex(ea),
                "reason": "pseudocode_render_exception",
                "exception_type": type(exc).__name__,
                "exception": str(exc),
            },
        ) from exc


def decompile_function_safe(
    ea: int, *, error_out: dict[str, Any] | None = None
) -> Optional[str]:
    """Safely decompile a function while logging and optionally returning details."""
    try:
        return decompile_function_detailed(ea)
    except DecompilationError as exc:
        if error_out is not None:
            error_out.update(exc.details)
            error_out["message"] = str(exc)
        try:
            from .sync import log_tool_diagnostic

            log_tool_diagnostic(
                "decompile_failed",
                addr=hex(ea),
                error=str(exc),
                details=exc.details,
            )
        except Exception:
            pass
        return None
    except Exception as exc:
        details = {
            "resolved_addr": hex(ea),
            "reason": "unexpected_exception",
            "exception_type": type(exc).__name__,
            "exception": str(exc),
        }
        if error_out is not None:
            error_out.update(details)
            error_out["message"] = f"Unexpected decompilation failure: {exc}"
        try:
            from .sync import log_tool_diagnostic

            log_tool_diagnostic(
                "decompile_failed",
                addr=hex(ea),
                error=repr(exc),
                details=details,
            )
        except Exception:
            pass
        return None


def disasm_text(ea: int) -> str:
    """Rendered listing text of the item at *ea*, tags removed."""
    line = ida_lines.generate_disasm_line(ea, 0)
    return ida_lines.tag_remove(line) if line else ""


def get_assembly_lines(ea: int) -> str:
    """Get assembly lines for a function in compact string format"""
    func = compat.get_func(ea)
    if not func:
        return ""
    func_name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
    segment_name = compat.get_segment_name(func.start_ea) or "UNKNOWN"
    lines = [f"{func_name} ({segment_name} @ {hex(func.start_ea)}):"]
    lines += [f"{ea:x}  {disasm_text(ea)}" for ea in idautils.FuncItems(func.start_ea)]
    return "\n".join(lines)


def get_all_xrefs(ea: int) -> dict:
    """Get all xrefs to and from an address"""
    return {
        "to": [
            {"addr": hex(x.frm), "type": "code" if x.iscode else "data"}
            for x in idautils.XrefsTo(ea, 0)
        ],
        "from": [
            {"addr": hex(x.to), "type": "code" if x.iscode else "data"}
            for x in idautils.XrefsFrom(ea, 0)
        ],
    }


def get_all_comments(ea: int) -> dict:
    """Get all comments for an address"""
    from . import compat

    func = compat.get_func(ea)
    if not func:
        return {}

    comments = {}
    for item_ea in idautils.FuncItems(func.start_ea):
        cmt = idaapi.get_cmt(item_ea, False)
        if cmt:
            comments[hex(item_ea)] = {"regular": cmt}
        cmt = idaapi.get_cmt(item_ea, True)
        if cmt:
            if hex(item_ea) not in comments:
                comments[hex(item_ea)] = {}
            comments[hex(item_ea)]["repeatable"] = cmt
    return comments


def _call_target(insn) -> int | None:
    op = insn.ops[0]
    if op.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
        return op.addr
    if op.type == ida_ua.o_imm:
        return op.value
    return None


def _collect_callees(func, call_only: bool) -> list[dict]:
    """Unique callees of *func* in address order as {addr, name, type}.

    Call instructions contribute their operand target (imports included, typed
    "external"). With call_only=False, jumps/tail calls into other functions count too.
    """
    callees: dict[int, dict] = {}
    for ea in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            continue
        if ida_idp.is_call_insn(insn):
            targets = [_call_target(insn)]
        elif call_only:
            continue
        else:
            targets = []
            for ref in idautils.CodeRefsFrom(ea, 0):
                callee = compat.get_func(ref)
                if callee and callee.start_ea != func.start_ea:
                    targets.append(callee.start_ea)
        for target in targets:
            if target is None or target in callees:
                continue
            callees[target] = {
                "addr": hex(target),
                "name": ida_name.get_name(target) or "",
                "type": "internal" if compat.get_func(target) else "external",
            }
    return list(callees.values())


def _collect_callers(func) -> list[Function]:
    """Unique functions that call *func*, in reference order."""
    callers: dict[int, Function] = {}
    for site in idautils.CodeRefsTo(func.start_ea, 0):
        caller = compat.get_func(site)
        if not caller or caller.start_ea in callers:
            continue
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, site) and ida_idp.is_call_insn(insn):
            callers[caller.start_ea] = get_function(caller.start_ea)
    return list(callers.values())


def get_callees(addr: str) -> list[dict]:
    """Get callees for a single function address"""
    func = compat.get_func(parse_address(addr))
    return _collect_callees(func, call_only=True) if func else []


def get_callers(addr: str, limit: int = 50) -> list[Function]:
    """Get callers for a single function address"""
    func = compat.get_func(parse_address(addr))
    return _collect_callers(func)[:limit] if func else []


def _segments(exec_only: bool) -> list[tuple[int, int]]:
    """[(start, end)] of segments in address order, optionally executable only."""
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = compat.get_segment_info(seg_ea)
        if seg and (not exec_only or compat.get_segment_perm(seg) & ida_segment.SEGPERM_EXEC):
            ranges.append((seg.start_ea, seg.end_ea))
    return ranges


def extract_function_strings(ea: int) -> list[String]:
    """Extract string references from a function"""
    from . import compat

    func = compat.get_func(ea)
    if not func:
        return []

    strings = []
    for item_ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(item_ea, 0):
            if not xref.iscode:
                # Check if target is a string
                str_type = ida_nalt.get_str_type(xref.to)
                if str_type != ida_nalt.STRTYPE_C:
                    continue
                try:
                    str_content = idc.get_strlit_contents(xref.to)
                    if str_content:
                        strings.append(
                            String(
                                addr=hex(xref.to),
                                length=len(str_content),
                                string=str_content.decode("utf-8", errors="replace"),
                            )
                        )
                except Exception:
                    pass
    return strings


def extract_function_constants(ea: int) -> list[dict]:
    """Extract immediate constants from a function"""
    from . import compat

    func = compat.get_func(ea)
    if not func:
        return []

    constants = []
    for item_ea in idautils.FuncItems(func.start_ea):
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, item_ea) > 0:
            for op in insn.ops:
                if op.type == idaapi.o_imm:
                    constants.append(
                        {
                            "addr": hex(item_ea),
                            "value": hex(op.value),
                            "decimal": op.value,
                        }
                    )
    return constants


