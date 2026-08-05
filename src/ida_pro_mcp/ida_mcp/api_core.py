"""Core API Functions - IDB metadata and basic queries"""

import re
import time
from typing import Annotated, Any, TypedDict

import ida_auto
import idaapi
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import idautils
import ida_loader
import ida_nalt
import ida_segment
import ida_typeinf
import idc

from . import compat
from .rpc import tool, unsafe
from .sync import (
    get_pending_ui_request_count,
    get_search_page_budget_seconds,
    get_tool_deadline,
    idasync,
)
from .utils import (
    ConvertedNumber,
    EntityQuery,
    Function,
    FunctionQuery,
    Global,
    Import,
    ListQuery,
    NumberConversion,
    Page,
    ImportQuery,
    get_function,
    normalize_dict_list,
    normalize_list_input,
    parse_address,
    paginate,
    pattern_filter,
)

# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None
_server_started_at = time.time()


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    if _strings_cache is None:
        _strings_cache = [(s.ea, str(s)) for s in idautils.Strings() if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


def init_caches():
    """Build caches on plugin startup (called from Ctrl+M)."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    print(f"[MCP] Cached {len(strings)} strings in {(t1 - t0) * 1000:.0f}ms")


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


def _coerce_sort_number(value, default: int = 0) -> int:
    """Parse decimal or prefixed string numbers used by generic entity rows."""
    if value in (None, ""):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _collect_imports() -> list[Import]:
    """Collect all imports in the current database."""
    all_imports: list[Import] = []
    nimps = ida_nalt.get_import_module_qty()

    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, all_imports)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return all_imports


def _segment_name_for_ea(ea: int) -> str | None:
    try:
        return ida_segment.get_segment_name(ea) or None
    except (AttributeError, TypeError):
        return None


def _get_func(ea: int):
    """Return function entry/range info without IDA 9.x deprecation warnings."""
    return compat.get_func(ea)


def _primary_text_key(kind: str) -> str:
    if kind == "strings":
        return "text"
    return "name"


def _collect_entities(kind: str) -> list[dict]:
    if kind == "functions":
        rows: list[dict] = []
        for ea in idautils.Functions():
            fn = _get_func(ea)
            if not fn:
                continue
            size_int = fn.end_ea - fn.start_ea
            rows.append(
                {
                    "kind": "function",
                    "addr": hex(fn.start_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                    "size": hex(size_int),
                    "size_int": size_int,
                    "segment": _segment_name_for_ea(fn.start_ea),
                    "has_type": bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)),
                }
            )
        return rows

    if kind == "globals":
        rows = []
        for ea, name in idautils.Names():
            if _get_func(ea) or name is None:
                continue
            rows.append(
                {
                    "kind": "global",
                    "addr": hex(ea),
                    "name": name,
                    "size": idc.get_item_size(ea),
                    "segment": _segment_name_for_ea(ea),
                }
            )
        return rows

    if kind == "imports":
        rows = []
        for imp in _collect_imports():
            rows.append(
                {
                    "kind": "import",
                    "addr": imp["addr"],
                    "name": imp["imported_name"],
                    "module": imp["module"],
                }
            )
        return rows

    if kind == "strings":
        rows = []
        for ea, text in _get_strings_cache():
            rows.append(
                {
                    "kind": "string",
                    "addr": hex(ea),
                    "text": text,
                    "length": len(text),
                    "segment": _segment_name_for_ea(ea),
                }
            )
        return rows

    if kind == "names":
        rows = []
        imports_by_ea = {int(imp["addr"], 16): imp for imp in _collect_imports()}
        for ea, name in idautils.Names():
            is_function = bool(_get_func(ea))
            is_import = ea in imports_by_ea
            rows.append(
                {
                    "kind": "name",
                    "addr": hex(ea),
                    "name": name,
                    "segment": _segment_name_for_ea(ea),
                    "is_function": is_function,
                    "is_import": is_import,
                }
            )
        return rows

    return []


def _apply_projection(items: list[dict], fields: list[str] | None) -> list[dict]:
    if not fields:
        return items
    normalized = [str(f).strip() for f in fields if str(f).strip()]
    if not normalized:
        return items
    keep = set(normalized)
    keep.add("kind")
    projected = []
    for item in items:
        projected.append({k: v for k, v in item.items() if k in keep})
    return projected


def _build_health_payload() -> dict:
    auto_is_ok = getattr(ida_auto, "auto_is_ok", None)
    auto_analysis_ready = bool(auto_is_ok()) if callable(auto_is_ok) else None

    hexrays_ready = False
    try:
        hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays_ready = False

    idb_path = None
    try:
        idb_path = idc.get_idb_path()
    except Exception:
        idb_path = None

    return {
        "status": "ok",
        "uptime_sec": round(time.time() - _server_started_at, 3),
        "idb_path": idb_path,
        "module": ida_nalt.get_root_filename(),
        "input_path": ida_nalt.get_input_file_path(),
        "imagebase": hex(idaapi.get_imagebase()),
        "auto_analysis_ready": auto_analysis_ready,
        "hexrays_ready": hexrays_ready,
        "strings_cache_ready": _strings_cache is not None,
        "strings_cache_size": len(_strings_cache) if _strings_cache is not None else 0,
    }


@tool
@idasync
def server_health() -> dict:
    """Health/ready probe for MCP server and current IDB state."""
    return _build_health_payload()


@tool
@idasync
def server_warmup(
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches (currently strings)"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler plugin"] = True,
) -> dict:
    """Warm up IDA subsystems to reduce first-call latency and transient failures."""
    steps = []

    if wait_auto_analysis:
        t0 = time.perf_counter()
        ida_auto.auto_wait()
        steps.append({"step": "auto_wait", "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 2)})

    if build_caches:
        t0 = time.perf_counter()
        init_caches()
        steps.append({"step": "init_caches", "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 2)})

    if init_hexrays:
        t0 = time.perf_counter()
        ok = bool(ida_hexrays.init_hexrays_plugin())
        steps.append(
            {
                "step": "init_hexrays",
                "ok": ok,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
                "error": None if ok else "Hex-Rays unavailable",
            }
        )

    return {
        "ok": all(bool(step.get("ok")) for step in steps),
        "steps": steps,
        "health": _build_health_payload(),
    }


@tool
@idasync
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
) -> list[dict]:
    """Get functions by address or name (auto-detects)"""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in queries:
        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
) -> list[dict]:
    """Convert numbers to different formats"""
    inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
                "error": None,
            }
        )

    return results


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List functions with optional filtering and pagination",
    ],
) -> list[Page[Function]]:
    """List functions with optional filtering and offset/count pagination."""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_functions = [get_function(addr) for addr in idautils.Functions()]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def func_query(
    queries: Annotated[
        list[FunctionQuery] | FunctionQuery | str,
        "Richer function query (size/type/name filters + pagination)",
    ],
) -> list[dict]:
    """Query functions with richer filtering than list_funcs."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "filter": s,
            "offset": 0,
            "count": 50,
            "sort_by": "addr",
            "descending": False,
        },
    )

    all_functions: list[dict] = []
    for addr in idautils.Functions():
        fn = _get_func(addr)
        if not fn:
            continue
        size_int = fn.end_ea - fn.start_ea
        fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
        has_type = ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)
        all_functions.append(
            {
                "addr": hex(fn.start_ea),
                "name": fn_name,
                "size": hex(size_int),
                "size_int": size_int,
                "has_type": has_type,
            }
        )

    def apply_name_regex(items: list[dict], expr: str) -> list[dict]:
        if not expr:
            return items
        try:
            compiled = re.compile(expr)
        except re.error:
            return []
        return [item for item in items if compiled.search(item["name"])]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 50)
        sort_by = query.get("sort_by", "addr")
        descending = bool(query.get("descending", False))
        if sort_by not in ("addr", "name", "size"):
            sort_by = "addr"

        filtered = all_functions
        name_filter = query.get("filter", "")
        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "name")

        name_regex = query.get("name_regex", "")
        if name_regex:
            filtered = apply_name_regex(filtered, name_regex)

        min_size = query.get("min_size")
        if min_size is not None:
            filtered = [f for f in filtered if f["size_int"] >= int(min_size)]

        max_size = query.get("max_size")
        if max_size is not None:
            filtered = [f for f in filtered if f["size_int"] <= int(max_size)]

        if "has_type" in query:
            require_type = bool(query.get("has_type"))
            filtered = [f for f in filtered if bool(f["has_type"]) is require_type]

        if sort_by == "name":
            filtered.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            filtered.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            filtered.sort(key=lambda f: int(f["addr"], 16), reverse=descending)

        page = paginate(filtered, offset, count)
        page["data"] = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]
        results.append(page)

    return results


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals with optional filtering and offset/count pagination."""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not _get_func(addr) and name is not None:
            all_globals.append(Global(addr=hex(addr), name=name))

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def entity_query(
    queries: Annotated[
        list[EntityQuery] | EntityQuery | str,
        "Generic entity query with filtering, projection, and pagination",
    ],
) -> list[dict]:
    """Query IDB entities with typed filters, projection, and pagination."""
    queries = normalize_dict_list(
        queries,
        lambda s: {"kind": s, "offset": 0, "count": 100, "sort_by": "addr"},
    )
    results: list[dict] = []

    for query in queries:
        kind = str(query.get("kind", "functions") or "functions").lower()
        if kind not in {"functions", "globals", "imports", "strings", "names"}:
            results.append(
                {
                    "kind": kind,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    "error": f"Unsupported kind: {kind}",
                }
            )
            continue

        rows = _collect_entities(kind)
        primary_key = _primary_text_key(kind)
        filter_pattern = str(query.get("filter", "") or "")
        if filter_pattern:
            rows = pattern_filter(rows, filter_pattern, primary_key)

        regex = str(query.get("regex", "") or "")
        if regex:
            try:
                compiled = re.compile(regex)
                rows = [row for row in rows if compiled.search(str(row.get(primary_key, "")))]
            except re.error:
                rows = []

        segment_filter = str(query.get("segment", "") or "")
        if segment_filter and kind in {"functions", "globals", "strings", "names"}:
            rows = pattern_filter(rows, segment_filter, "segment")

        module_filter = str(query.get("module", "") or "")
        if module_filter and kind == "imports":
            rows = pattern_filter(rows, module_filter, "module")

        min_addr = query.get("min_addr")
        if min_addr not in (None, ""):
            try:
                min_ea = parse_address(min_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) >= min_ea]
            except Exception:
                rows = []

        max_addr = query.get("max_addr")
        if max_addr not in (None, ""):
            try:
                max_ea = parse_address(max_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) <= max_ea]
            except Exception:
                rows = []

        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))
        if sort_by == "addr":
            rows.sort(key=lambda row: int(str(row.get("addr", "0x0")), 16), reverse=descending)
        elif sort_by in {"size", "length"}:
            rows.sort(
                key=lambda row: row.get("size_int", _coerce_sort_number(row.get(sort_by, 0))),
                reverse=descending,
            )
        else:
            rows.sort(key=lambda row: str(row.get(sort_by, "")).lower(), reverse=descending)

        offset = int(query.get("offset", 0) or 0)
        count = int(query.get("count", 100) or 100)
        page = paginate(rows, offset, count)
        data = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]

        fields_raw = query.get("fields")
        fields = None
        if fields_raw is not None:
            if isinstance(fields_raw, str):
                fields = normalize_list_input(fields_raw)
            elif isinstance(fields_raw, list):
                fields = [str(f) for f in fields_raw]
            else:
                fields = [str(fields_raw)]
        data = _apply_projection(data, fields)

        results.append(
            {
                "kind": kind,
                "data": data,
                "next_offset": page["next_offset"],
                "total": len(rows),
                "error": None,
            }
        )

    return results


@tool
@idasync
def imports(
    offset: Annotated[int, "Starting pagination index (default: 0)"],
    count: Annotated[int, "Maximum rows (0 returns all imports)"],
) -> Page[Import]:
    """List imports with module names using offset/count pagination."""
    return paginate(_collect_imports(), offset, count)


@tool
@idasync
def imports_query(
    queries: Annotated[
        list[ImportQuery] | ImportQuery | str,
        "Import query with import/module filters and pagination",
    ],
) -> list[dict]:
    """Query imports with richer filtering than imports(offset,count)."""
    queries = normalize_dict_list(
        queries, lambda s: {"filter": s, "offset": 0, "count": 100}
    )
    all_imports = _collect_imports()
    results = []

    for query in queries:
        filtered = all_imports
        name_filter = query.get("filter", "")
        module_filter = query.get("module", "")

        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "imported_name")
        if module_filter:
            filtered = pattern_filter(filtered, module_filter, "module")

        results.append(
            paginate(filtered, query.get("offset", 0), query.get("count", 100))
        )

    return results


@tool
@idasync
@unsafe
def idb_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
) -> dict:
    """Save active IDB to disk, optionally to a provided path."""
    try:
        save_path = path.strip() if path else ""
        if not save_path:
            save_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

        ok = bool(ida_loader.save_database(save_path, 0))
        return {
            "ok": ok,
            "path": save_path,
            "error": None if ok else "save_database returned false",
        }
    except Exception as e:
        return {"ok": False, "path": path or None, "error": str(e)}


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in strings"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> dict:
    """Search strings by case-insensitive regex with offset/limit pagination."""
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    matches = []
    regex = re.compile(pattern, re.IGNORECASE)
    strings = _get_strings_cache()

    skipped = 0
    more = False
    for ea, text in strings:
        if regex.search(text):
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                more = True
                break
            matches.append({"addr": hex(ea), "string": text})

    return {
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }


# ============================================================================
# Listing text search
# ============================================================================


class SearchTextLine(TypedDict, total=False):
    kind: str  # "disasm" | "comment"
    text: str


class SearchTextHit(TypedDict, total=False):
    addr: str
    function: str
    segment: str
    matches: list[SearchTextLine]


class SearchTextResult(TypedDict, total=False):
    n: int
    hits: list[SearchTextHit]
    cursor: dict[str, Any]
    error: str
    elapsed_ms: float
    partial: bool
    reason: str
    queue_depth: int


def _classify_hit_lines(
    ea: int,
    matcher,
    want_disasm: bool,
    want_comments: bool,
    max_lines: int = 32,
) -> list[SearchTextLine]:
    """Match disasm/comment text at *ea* without spamming IDA's Output window.

    Uses ``generate_disasm_line`` (one instruction line) plus explicit comment
    getters. Avoid ``generate_disassembly``: when a head expands past
    ``max_lines``, IDA prints ``Too many lines`` for every such address.
    """
    del max_lines  # retained for call-site compatibility
    out: list[SearchTextLine] = []

    if want_disasm:
        try:
            tagged = ida_lines.generate_disasm_line(ea, 0) or ""
        except Exception:
            tagged = ""
        text = ida_lines.tag_remove(tagged) if tagged else ""
        if text and matcher(text):
            out.append({"kind": "disasm", "text": text})

    if want_comments:
        comments: list[str] = []
        try:
            for repeatable in (False, True):
                cmt = ida_bytes.get_cmt(ea, repeatable)
                if cmt:
                    comments.append(cmt)
            # Anterior/posterior extra comments (function banners, etc.).
            for base in (ida_lines.E_PREV, ida_lines.E_NEXT):
                idx = base
                for _ in range(64):
                    extra = ida_lines.get_extra_cmt(ea, idx)
                    if not isinstance(extra, str) or not extra:
                        break
                    comments.append(extra)
                    idx += 1
        except Exception:
            pass

        seen: set[str] = set()
        for cmt in comments:
            text = cmt.strip()
            if not text or text in seen or not matcher(text):
                continue
            seen.add(text)
            out.append({"kind": "comment", "text": text})

    return out


def _exec_segments() -> list[tuple[int, int]]:
    """Return [(start, end)] for executable segments in address order."""
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = compat.get_segment_info(seg_ea)
        if not seg:
            continue
        perm = seg.get_perm() if hasattr(seg, "get_perm") else getattr(seg, "perm", 0)
        if not (perm & idaapi.SEGPERM_EXEC):
            continue
        ranges.append((seg.start_ea, seg.end_ea))
    return ranges


def _all_segments() -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = compat.get_segment_info(seg_ea)
        if seg:
            ranges.append((seg.start_ea, seg.end_ea))
    return ranges


@tool
@idasync
def search_text(
    pattern: Annotated[str, "Text to search for in the rendered listing (literal substring by default)"],
    limit: Annotated[int, "Max hits per page (default: 30, max: 500)"] = 30,
    start: Annotated[str, "Lower bound (hex or symbol). Empty = first segment."] = "",
    end: Annotated[str, "Upper bound (hex or symbol, exclusive). Empty = last segment."] = "",
    regex: Annotated[bool, "Treat pattern as a Python regex"] = False,
    case_sensitive: Annotated[bool, "Case-sensitive match (default: false)"] = False,
    include: Annotated[str, "'disasm' | 'comments' | 'all' (default: all)"] = "all",
    code_only: Annotated[bool, "Restrict search to executable segments (default: true)"] = True,
) -> SearchTextResult:
    """Search the rendered listing for `pattern` over [start, end).

    Iterates `idautils.Heads()` and matches each head via
    `ida_lines.generate_disasm_line()` plus comment getters. Per-head
    work is cheap and yields between heads. Each page has a bounded time
    budget and returns a continuation cursor before common MCP client timeouts.
    """
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    include = (include or "all").lower()
    if include not in ("disasm", "comments", "all"):
        return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid include: {include!r}"}

    want_disasm = include in ("disasm", "all")
    want_comments = include in ("comments", "all")

    if regex:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            rx = re.compile(pattern, flags)
        except re.error as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid regex: {e}"}
        def matcher(text: str) -> bool:
            return bool(rx.search(text))

    elif case_sensitive:
        needle = pattern

        def matcher(text: str) -> bool:
            return needle in text

    else:
        needle = pattern.lower()

        def matcher(text: str) -> bool:
            return needle in text.lower()

    segments = _exec_segments() if code_only else _all_segments()
    if not segments:
        return {"n": 0, "hits": [], "cursor": {"done": True}}

    if start:
        try:
            start_ea = parse_address(start)
        except Exception as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid start: {e}"}
    else:
        start_ea = segments[0][0]

    if end:
        try:
            end_ea = parse_address(end)
        except Exception as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid end: {e}"}
    else:
        end_ea = segments[-1][1]

    if end_ea <= start_ea:
        return {"n": 0, "hits": [], "cursor": {"done": True}}

    hits: list[SearchTextHit] = []
    next_cursor: int | None = None
    stopped = False
    stop_reason: str | None = None
    CHUNK_BYTES = 65536
    started_at = time.monotonic()
    page_deadline = started_at + get_search_page_budget_seconds()
    contended_page_deadline = started_at + get_search_page_budget_seconds(
        contended=True
    )
    page_deadline_reason = "time_budget"
    tool_deadline = get_tool_deadline()
    if tool_deadline is not None and tool_deadline < page_deadline:
        page_deadline = tool_deadline
        page_deadline_reason = "tool_deadline"

    def current_stop_reason() -> str | None:
        if ida_kernwin.user_cancelled():
            return "cancelled"
        now = time.monotonic()
        if now >= page_deadline:
            return page_deadline_reason
        if (
            now >= contended_page_deadline
            and get_pending_ui_request_count() > 0
        ):
            return "queue_pressure"
        return None

    for seg_start, seg_end in segments:
        if stopped or len(hits) >= limit:
            break
        if seg_end <= start_ea:
            continue
        if seg_start >= end_ea:
            break
        walk_start = max(seg_start, start_ea)
        walk_end = min(seg_end, end_ea)
        chunk_ea = walk_start
        while chunk_ea < walk_end:
            if stopped or len(hits) >= limit:
                break
            reason = current_stop_reason()
            if reason is not None:
                stopped = True
                stop_reason = reason
                next_cursor = chunk_ea
                break
            chunk_end = min(chunk_ea + CHUNK_BYTES, walk_end)
            for heads_seen, head_ea in enumerate(idautils.Heads(chunk_ea, chunk_end)):
                if heads_seen % 64 == 0:
                    reason = current_stop_reason()
                    if reason is not None:
                        stopped = True
                        stop_reason = reason
                        next_cursor = head_ea
                        break
                lines = _classify_hit_lines(head_ea, matcher, want_disasm, want_comments)
                if not lines:
                    continue
                entry: SearchTextHit = {"addr": hex(head_ea), "matches": lines}
                func = compat.get_func(head_ea)
                if func is not None:
                    fname = ida_funcs.get_func_name(func.start_ea)
                    if fname:
                        entry["function"] = fname
                sname = compat.get_segment_name(head_ea)
                if sname:
                    entry["segment"] = sname
                hits.append(entry)
                if len(hits) >= limit:
                    size = max(1, idaapi.get_item_size(head_ea))
                    next_cursor = head_ea + size
                    break
            chunk_ea = chunk_end

    cursor: dict[str, Any]
    if stop_reason is not None:
        resume_ea = next_cursor if next_cursor is not None else start_ea
        cursor = {
            "next": hex(resume_ea),
            "partial": True,
            "reason": stop_reason,
        }
        if stop_reason == "cancelled":
            cursor["cancelled"] = True
    elif next_cursor is not None:
        cursor = {"next": hex(next_cursor)}
    else:
        cursor = {"done": True}

    elapsed_ms = round((time.monotonic() - started_at) * 1000, 3)
    queue_depth = (
        get_pending_ui_request_count() if stop_reason == "queue_pressure" else 0
    )
    return {
        "n": len(hits),
        "hits": hits,
        "cursor": cursor,
        "elapsed_ms": elapsed_ms,
        "partial": stop_reason is not None,
        "reason": stop_reason or "complete",
        "queue_depth": queue_depth,
    }
