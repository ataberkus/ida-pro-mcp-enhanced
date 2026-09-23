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
import ida_strlist
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
    resolve_address_or_name,
    clamp_int,
    paginate,
    pattern_filter,
    _segments,
)

# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None
_server_started_at = time.time()


def _decode_strlist_item(si: "ida_strlist.string_info_t") -> str:
    """Decode a strlist item to text without constructing idautils.Strings()."""
    if getattr(si, "type", None) == ida_nalt.STRTYPE_DECOMP:
        text = getattr(si, "decompiler_string", "") or ""
        return text if isinstance(text, str) else str(text)
    raw = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
    if not raw:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode("UTF-8", "replace")
    return str(raw)


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access.

    Uses the existing IDA string list. Does NOT call idautils.Strings(),
    which always rebuilds via build_strlist() and can take minutes on large IDBs.
    """
    global _strings_cache
    if _strings_cache is None:
        qty = int(ida_strlist.get_strlist_qty())
        # Only build when the list is empty; never force a full rebuild on cache miss.
        if qty <= 0:
            ida_strlist.build_strlist()
            qty = int(ida_strlist.get_strlist_qty())
        built: list[tuple[int, str]] = []
        si = ida_strlist.string_info_ex_t()
        for idx in range(qty):
            if not ida_strlist.get_strlist_item_ex(si, idx):
                continue
            built.append((si.ea, _decode_strlist_item(si)))
        _strings_cache = built
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


def _primary_text_key(kind: str) -> str:
    if kind == "strings":
        return "text"
    return "name"


def _collect_entities(kind: str, query: dict | None = None) -> list[dict]:
    if kind == "functions":
        rows: list[dict] = []
        for ea in idautils.Functions():
            fn = compat.get_func(ea)
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
                    "segment": compat.get_segment_name(fn.start_ea),
                    "has_type": bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)),
                }
            )
        return rows

    if kind == "globals":
        rows = []
        for ea, name in idautils.Names():
            if compat.get_func(ea) or name is None:
                continue
            rows.append(
                {
                    "kind": "global",
                    "addr": hex(ea),
                    "name": name,
                    "size": idc.get_item_size(ea),
                    "segment": compat.get_segment_name(ea),
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
                    "segment": compat.get_segment_name(ea),
                }
            )
        return rows

    if kind == "names":
        rows = []
        imports_by_ea = {int(imp["addr"], 16): imp for imp in _collect_imports()}
        for ea, name in idautils.Names():
            is_function = bool(compat.get_func(ea))
            is_import = ea in imports_by_ea
            rows.append(
                {
                    "kind": "name",
                    "addr": hex(ea),
                    "name": name,
                    "segment": compat.get_segment_name(ea),
                    "is_function": is_function,
                    "is_import": is_import,
                }
            )
        return rows

    if kind in {"switches", "patches", "classes", "vtables", "signatures", "type_libraries"}:
        from . import api_recovery

        if kind == "switches":
            return api_recovery.collect_switches(api_recovery.resolve_switch_targets(query or {}))
        if kind == "patches":
            return api_recovery.collect_patches()
        if kind in {"classes", "vtables"}:
            return api_recovery.collect_classes()
        if kind == "signatures":
            return api_recovery.collect_signature_files()
        return api_recovery.collect_type_libraries()


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
    """Legacy health probe (no canonical equivalent; server_capabilities covers runtime caps).
    WHEN: check MCP server liveness and current IDB/analysis state.
    RETURNS: {ok?, auto_analysis_ready?, idb path/arch/functions?...} health payload.
    LIMITS: point-in-time snapshot; auto-analysis may still be running after ok."""
    return _build_health_payload()


@tool
@idasync
def server_warmup(
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches (currently strings)"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler plugin"] = True,
) -> dict:
    """Legacy warmup (no canonical equivalent).
    WHEN: reduce first-call latency by waiting auto-analysis, building caches, initing Hex-Rays.
    RETURNS: {ok, steps[{step, ok, ms, error?}], health}.
    LIMITS: may take seconds; init_hexrays reports ok=false when Hex-Rays is unavailable."""
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
    """Prefer entity_query(kind="functions", ...) for filtered/paginated lookup.
    WHEN: resolve exact addresses/names to function records (auto-detects; "*" lists all).
    RETURNS: [{query, fn, error}] per query.
    LIMITS: "*" caps at 1000 functions; non-function addresses report "Not a function"/"Not found"."""
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
    """Canonical number conversion (listed in CANONICAL_TOOLS).
    WHEN: render numbers as decimal/hex/bytes/ascii/binary (string form means {"text": s, size 64}).
    RETURNS: [{input, result{decimal, hexadecimal, bytes, ascii, binary}, error}] per input.
    LIMITS: unparsable text and values too big for size return error entries, result None."""
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
            size = 0 if value == 0 else (value.bit_length() + 8) // 8

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
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """Prefer entity_query(kind="globals", ...) for filtered/paginated listing.
    WHEN: list data globals (non-function named addresses) with glob filter + offset/count.
    RETURNS: [{data, next_offset, total, ...}] page per query.
    LIMITS: default count 50 (query count defaults 100); empty/"*" filter means all names."""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not compat.get_func(addr) and name is not None:
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
    """Canonical entity search (listed in CANONICAL_TOOLS).
    WHEN: filtered/paginated listing of functions|globals|imports|strings|names|switches|patches|classes|vtables|signatures|type_libraries with glob/regex filter, projection, sorting.
    RETURNS: [{kind, data[rows], next_offset, total, error}] per query.
    LIMITS: count max 5000; bad kind returns an error entry listing Allowed values; regex errors surface in error, not raises."""
    queries = normalize_dict_list(
        queries,
        lambda s: {"kind": s, "offset": 0, "count": 100, "sort_by": "addr"},
    )
    results: list[dict] = []

    for query in queries:
        kind = str(query.get("kind", "functions") or "functions").lower()
        allowed_entity_kinds = ("functions", "globals", "imports", "strings", "names", "switches", "patches", "classes", "vtables", "signatures", "type_libraries")
        if kind not in set(allowed_entity_kinds):
            results.append(
                {
                    "kind": kind,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    "error": f"Unsupported kind: {kind}. Allowed: {', '.join(allowed_entity_kinds)}",
                }
            )
            continue

        rows = _collect_entities(kind, query)
        primary_key = _primary_text_key(kind)
        filter_pattern = str(query.get("filter", "") or "")
        if filter_pattern:
            rows = pattern_filter(rows, filter_pattern, primary_key)

        query_error = None
        regex = str(query.get("regex", "") or "")
        if regex:
            try:
                flags = 0 if query.get("case_sensitive", True) else re.IGNORECASE
                compiled = re.compile(regex, flags)
                rows = [row for row in rows if compiled.search(str(row.get(primary_key, "")))]
            except re.error as exc:
                query_error = f"Invalid regex: {exc}"
                rows = []

        segment_filter = str(query.get("segment", "") or "")
        if segment_filter and kind in {"functions", "globals", "strings", "names"}:
            rows = pattern_filter(rows, segment_filter, "segment")

        module_filter = str(query.get("module", "") or "")
        if module_filter and kind == "imports":
            rows = pattern_filter(rows, module_filter, "module")

        min_addr = query.get("min_addr")
        if min_addr not in (None, "") and query_error is None:
            try:
                min_ea = resolve_address_or_name(min_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) >= min_ea]
            except Exception:
                query_error = f"Invalid min_addr: {min_addr!r}"
                rows = []

        max_addr = query.get("max_addr")
        if max_addr not in (None, "") and query_error is None:
            try:
                max_ea = resolve_address_or_name(max_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) <= max_ea]
            except Exception:
                query_error = f"Invalid max_addr: {max_addr!r}"
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

        offset = clamp_int(query.get("offset", 0), 0, 0, 2_000_000_000)
        count = clamp_int(query.get("count", 100), 100, 0, 5000)
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
                "error": query_error,
            }
        )

    return results


def _query_imports(queries: list[dict]) -> list[Page[Import]]:
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
def imports(
    offset: Annotated[int, "Starting pagination index (default: 0)"],
    count: Annotated[int, "Maximum rows (0 returns all imports)"],
) -> Page[Import]:
    """Prefer entity_query(kind="imports", ...) for filtered/paginated import listing.
    WHEN: page the whole import table by offset/count with no filtering.
    RETURNS: {data[Import], next_offset, total, ...} page.
    LIMITS: count=0 returns all imports; no name/module filter (use imports_query/entity_query)."""
    return _query_imports([{"offset": offset, "count": count}])[0]


@tool
@idasync
def imports_query(
    queries: Annotated[
        list[ImportQuery] | ImportQuery | str,
        "Import query with import/module filters and pagination",
    ],
) -> list[dict]:
    """Prefer entity_query(kind="imports", filter=..., module=...) for unified entity search.
    WHEN: query imports with name/module filters plus offset/count pagination.
    RETURNS: [{data[Import], next_offset, total, ...}] page per query.
    LIMITS: filter/module are glob patterns; string form means {"filter": s, offset 0, count 100}."""
    return _query_imports(
        normalize_dict_list(queries, lambda s: {"filter": s, "offset": 0, "count": 100})
    )


@tool
@idasync
@unsafe
def idb_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
) -> dict:
    """Prefer mutation_preview(kind="save_database", ...) to stage a save through transactions.
    WHEN: save the active IDB now, optionally to another path (FILESYSTEM scope, immediate).
    RETURNS: {ok, path, error}.
    LIMITS: empty path saves to the current IDB path; destructive overwrite of the target path."""
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
) -> list[SearchTextLine]:
    """Match disasm/comment text at *ea* without spamming IDA's Output window.

    Uses ``generate_disasm_line`` (one instruction line) plus explicit comment
    getters. Avoid ``generate_disassembly``: when a head expands past its
    line limit, IDA prints ``Too many lines`` for every such address.
    """
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
    """Prefer search(kind="text", targets=[pattern], ...) for unified search with opaque cursor.
    WHEN: full-listing substring/regex search over disasm+comments within [start, end).
    RETURNS: {n, hits[{addr, function, segment, matches[{kind, text}]}], cursor, error?, partial?, reason?}.
    LIMITS: limit max 500; each page has a time budget (partial+reason set; continue via cursor); code_only skips data segments."""
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

    segments = _segments(exec_only=code_only)
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
