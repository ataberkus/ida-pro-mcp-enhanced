"""Binary survey tool -- complete triage in one call."""

from __future__ import annotations

from itertools import islice
from typing import Annotated

from ida_pro_mcp.vnext.triage import (
    IMPORT_CATEGORIES,
    classify_import,
    is_junk_string,
    is_loader_string,
    is_runtime_function_name,
    string_kind,
    string_score,
)

from .rpc import tool
from .sync import IDAError, idasync, tool_timeout
from . import compat
from .api_core import _get_strings_cache
from .utils import get_image_size

# Max functions to score on large binaries.
_MAX_FUNC_ITER = 10_000

# Max strings to examine for interesting_strings (perf cap).
_MAX_STRING_ITER = 5_000

# Max xrefs to materialize per string/function.
_MAX_XREFS_PER_STRING = 200
_MAX_XREFS_PER_FUNC = 200

_MAX_STRING_CHARS = 120

# detail_level -> canonical level; minimal/standard are legacy aliases.
_LEVELS = {"fast": "fast", "minimal": "fast", "full": "full", "standard": "full"}
_LIMITS = {
    "fast": {"top": 10, "per_category": 5, "entrypoints": 50},
    "full": {"top": 25, "per_category": 20, "entrypoints": 200, "roots": 25},
}

# Loader/import/metadata sections: strings here are symbol tables, not program text.
_LOADER_SEGMENTS = {
    ".interp", ".dynstr", ".dynsym", ".gnu.version", ".gnu.version_r", ".gnu.version_d",
    ".gnu.hash", ".hash", ".rela.dyn", ".rela.plt", ".rel.dyn", ".rel.plt", ".dynamic",
    ".got", ".got.plt", ".idata", ".edata", "extern", ".plt", ".plt.got", ".plt.sec",
    ".init_array", ".fini_array", ".eh_frame", ".eh_frame_hdr", ".comment",
    ".note.gnu.build-id", ".note.ABI-tag", ".note.gnu.property",
}
# Segments whose functions are import/PLT stubs or compiler init glue.
_STUB_FUNC_SEGMENTS = {".plt", ".plt.got", ".plt.sec", "extern", ".idata", ".init", ".fini"}

_MAIN_NAMES = (
    "main", "_main", "wmain", "_wmain", "WinMain", "wWinMain", "_WinMain@16",
    "_wWinMain@16", "DllMain", "_DllMain@12",
)

# Tiny wrapper threshold: at most one callee and fewer bytes than this.
_TINY_FUNC_BYTES = 48


def _display(ea: int) -> str:
    from .utils import display_name

    return display_name(ea)


def _seg_name(ea: int) -> str:
    return compat.get_segment_name(ea) or ""


def _is_exec(ea: int) -> bool:
    import ida_segment

    seg = compat.get_segment_info(ea)
    return bool(seg and compat.get_segment_perm(seg) & ida_segment.SEGPERM_EXEC)


def _build_metadata() -> dict:
    import idaapi
    import idc
    import ida_nalt

    path = idc.get_idb_path()
    module = ida_nalt.get_root_filename()
    base = hex(idaapi.get_imagebase())
    size = hex(get_image_size())
    is_64 = compat.inf_is_64bit()

    input_path = ida_nalt.get_input_file_path()
    from .utils import hash_input_file

    hashed = hash_input_file(input_path)
    md5 = hashed["md5"]
    sha256 = hashed["sha256"]

    return {
        "path": path,
        "module": module,
        "arch": "64" if is_64 else "32",
        "base_address": base,
        "image_size": size,
        "md5": md5,
        "sha256": sha256,
    }


def _build_segments() -> list[dict]:
    import idautils
    import ida_segment

    segments = []
    for seg_ea in idautils.Segments():
        seg = compat.get_segment_info(seg_ea)
        if not seg:
            continue
        perm = compat.get_segment_perm(seg)
        perms = []
        if perm & ida_segment.SEGPERM_READ:
            perms.append("r")
        if perm & ida_segment.SEGPERM_WRITE:
            perms.append("w")
        if perm & ida_segment.SEGPERM_EXEC:
            perms.append("x")
        segments.append({
            "name": compat.get_segment_name(seg_ea),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": hex(seg.end_ea - seg.start_ea),
            "permissions": "".join(perms) or "---",
        })
    return segments


def _build_entrypoints() -> list[dict]:
    """Entry rows; `ordinal` only for real exports (IDA uses ordinal == ea otherwise)."""
    entrypoints = []
    for i in range(compat.get_entry_qty()):
        ordinal = compat.get_entry_ordinal(i)
        ea = compat.get_entry(ordinal)
        row = {"addr": hex(ea), "name": _display(ea) or compat.get_entry_name(ordinal) or hex(ea)}
        if ordinal != ea:
            row["ordinal"] = ordinal
        entrypoints.append(row)
    return entrypoints


def _build_statistics(func_eas: list[int], string_count: int, segment_count: int) -> dict:
    import idaapi
    import idc

    total = len(func_eas)
    named = 0
    library = 0
    unnamed = 0

    for ea in func_eas:
        name = idc.get_name(ea, 0) or ""
        func = compat.get_func(ea)
        flags = compat.get_func_flags(func)

        if name.startswith("sub_"):
            unnamed += 1
        elif flags & idaapi.FUNC_LIB:
            library += 1
        else:
            named += 1

    return {
        "total_functions": total,
        "named_functions": named,
        "library_functions": library,
        "unnamed_functions": unnamed,
        "total_strings": string_count,
        "total_segments": segment_count,
    }


def _collect_imports() -> list[tuple[int, str, str]]:
    """All imports as (ea, name, module)."""
    import ida_nalt

    entries: list[tuple[int, str, str]] = []
    for i in range(ida_nalt.get_import_module_qty()):
        module = ida_nalt.get_import_module_name(i) or ""

        def imp_cb(ea: int, symbol_name: str | None, ordinal: int) -> bool:
            entries.append((ea, symbol_name or f"#{ordinal}", module))
            return True

        ida_nalt.enum_import_names(i, imp_cb)
    return entries


def _build_imports_by_category(imports: list[tuple[int, str, str, str]], per_category: int) -> dict:
    groups: dict[str, list[str]] = {}
    for ea, name, _module, category in imports:
        shown = _display(ea) if name.startswith(("?", "_Z")) else name
        groups.setdefault(category, []).append(shown)
    return {
        category: {"count": len(groups[category]), "items": groups[category][:per_category]}
        for category in (*IMPORT_CATEGORIES, "other")
        if groups.get(category)
    }


def _code_side(ea: int) -> bool:
    import ida_bytes

    return ida_bytes.is_code(ida_bytes.get_flags(ea)) or _is_exec(ea)


def _build_interesting_strings(import_names: set[str], limit: int) -> tuple[list[dict], set[int]]:
    """Rank program strings; returns (top rows, eas of every string that passed the filters).

    Skipped: strings in executable or loader/import sections, loader/version/import-name
    strings, byte junk. Kept only if referenced from code or informative (url/path/...)."""
    import idautils

    scored: list[tuple[int, int, int, str, str | None]] = []
    for ea, s in islice(_get_strings_cache(), _MAX_STRING_ITER):
        text = s.strip()
        if (
            _seg_name(ea) in _LOADER_SEGMENTS
            or _code_side(ea)
            or is_loader_string(text, import_names)
            or is_junk_string(text)
        ):
            continue
        refs = sum(
            1
            for xref in islice(idautils.XrefsTo(ea, 0), _MAX_XREFS_PER_STRING)
            if not xref.iscode and _code_side(xref.frm)
        )
        kind = string_kind(text)
        if not refs and not kind:
            continue
        scored.append((string_score(text, refs), refs, ea, s, kind))

    scored.sort(key=lambda t: (-t[0], -t[1], t[2]))
    rows = []
    for _score, refs, ea, text, kind in scored[:limit]:
        if len(text) > _MAX_STRING_CHARS:
            text = text[: _MAX_STRING_CHARS - 1] + "…"
        row = {"addr": hex(ea), "string": text, "xref_count": refs}
        if kind:
            row["kind"] = kind
        rows.append(row)
    return rows, {t[2] for t in scored}


class _FunctionScanner:
    """Per-function features shared by function ranking and the call-graph summary."""

    def __init__(self, import_categories: dict[int, str], string_eas: set[int]):
        self.import_categories = import_categories
        self.string_eas = string_eas
        self._callee_category: dict[int, str | None] = {}

    def _category_of_target(self, target: int) -> str | None:
        """Import category of a call/data target: IAT slot, extern symbol, or thunk to one."""
        if target in self._callee_category:
            return self._callee_category[target]
        import idaapi
        import ida_funcs
        import idc

        category = self.import_categories.get(target)
        if category is None:
            func = compat.get_func(target)
            if func and func.start_ea == target and compat.get_func_flags(func) & idaapi.FUNC_THUNK:
                try:
                    res = ida_funcs.calc_thunk_func_target(func)
                except Exception:
                    res = idaapi.BADADDR
                for cand in res if isinstance(res, (tuple, list)) else (res,):
                    category = self.import_categories.get(cand)
                    if category is None and cand != idaapi.BADADDR and _seg_name(cand) in ("extern", ".idata"):
                        category = classify_import(idc.get_name(cand, 0) or "")
                    if category:
                        break
        if category == "other":
            category = None
        self._callee_category[target] = category
        return category

    def scan(self, ea: int) -> dict | None:
        import idaapi
        import idautils
        import idc

        func = compat.get_func(ea)
        if not func:
            return None
        flags = compat.get_func_flags(func)
        size = compat.get_func_end_ea(func) - func.start_ea
        callees: set[int] = set()
        categories: set[str] = set()
        string_refs = 0
        for item_ea in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item_ea, 0):
                to = xref.to
                if xref.iscode:
                    if xref.type not in (idaapi.fl_CF, idaapi.fl_CN):
                        continue
                    callees.add(to)
                elif to in self.string_eas:
                    string_refs += 1
                category = self._category_of_target(to)
                if category:
                    categories.add(category)

        xref_count = 0
        caller_count = 0
        for xref in islice(idautils.XrefsTo(ea, 0), _MAX_XREFS_PER_FUNC):
            if xref.iscode and xref.type == idaapi.fl_F:
                continue
            xref_count += 1
            if xref.iscode and xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                caller_count += 1

        raw_name = idc.get_name(ea, 0) or ""
        noise = bool(flags & (idaapi.FUNC_THUNK | idaapi.FUNC_LIB)) or _seg_name(ea) in _STUB_FUNC_SEGMENTS
        name = raw_name if noise else _display(ea)
        if not noise:
            noise = (
                is_runtime_function_name(raw_name)
                or is_runtime_function_name(name)
                or (size < _TINY_FUNC_BYTES and len(callees) <= 1)
            )
        return {
            "ea": ea,
            "name": name,
            "size": size,
            "xref_count": xref_count,
            "caller_count": caller_count,
            "callees": callees,
            "categories": categories,
            "string_refs": string_refs,
            "noise": noise,
        }


def _function_score(feat: dict, exported: bool) -> tuple[int, list[str]]:
    """score = 4/import category called + 2/string ref (max 5) + callers (max 10)
    + callees/2 (max 5) + size/256 (max 4) + 3 if exported."""
    reasons = []
    if exported:
        reasons.append("export")
    reasons += [f"calls:{c}" for c in sorted(feat["categories"])]
    if feat["string_refs"]:
        reasons.append("refs:strings")
    if feat["xref_count"] >= 5:
        reasons.append("many_callers")
    if len(feat["callees"]) >= 10:
        reasons.append("many_callees")
    if feat["size"] >= 1024:
        reasons.append("large")
    score = (
        4 * len(feat["categories"])
        + 2 * min(feat["string_refs"], 5)
        + min(feat["xref_count"], 10)
        + min(len(feat["callees"]), 10) // 2
        + min(feat["size"] // 256, 4)
        + (3 if exported else 0)
    )
    return score, reasons


def _forced_functions() -> dict[int, str]:
    """Program entry and main-like functions, always listed: ea -> reason tag."""
    import idaapi
    import idc
    import ida_name

    forced: dict[int, str] = {}
    start = idc.get_inf_attr(idc.INF_START_EA)
    if start not in (None, idaapi.BADADDR) and compat.get_func(start):
        forced[compat.get_func(start).start_ea] = "entry"
    for name in _MAIN_NAMES:
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea != idaapi.BADADDR and compat.get_func(ea):
            forced.setdefault(compat.get_func(ea).start_ea, "main")
    return forced


def _build_interesting_functions(
    features: dict[int, dict], scanner: _FunctionScanner, exported: set[int], limit: int
) -> list[dict]:
    forced = _forced_functions()
    ranked: list[tuple[int, int, dict, list[str]]] = []
    for ea, feat in features.items():
        if feat["noise"] or ea in forced:
            continue
        score, reasons = _function_score(feat, ea in exported)
        ranked.append((score, ea, feat, reasons))
    ranked.sort(key=lambda t: (-t[0], t[1]))

    picks: list[tuple[dict, list[str]]] = []
    for ea, tag in forced.items():
        feat = features.get(ea) or scanner.scan(ea)
        if feat:
            picks.append((feat, [tag, *_function_score(feat, ea in exported)[1]]))
    picks += [(feat, reasons) for _score, _ea, feat, reasons in ranked]

    return [
        {
            "addr": hex(feat["ea"]),
            "name": feat["name"],
            "size": feat["size"],
            "xref_count": feat["xref_count"],
            "callee_count": len(feat["callees"]),
            "reasons": reasons,
        }
        for feat, reasons in picks[:limit]
    ]


def _build_call_graph_summary(features: dict[int, dict], max_roots: int) -> dict:
    """Distinct caller->callee call edges; roots are non-noise functions nobody calls."""
    roots = [f["name"] for f in features.values() if not f["noise"] and not f["caller_count"]]
    return {
        "call_edges": sum(len(f["callees"]) for f in features.values()),
        "root_count": len(roots),
        "root_functions": roots[:max_roots],
        "leaf_functions_count": sum(1 for f in features.values() if not f["callees"]),
    }


@tool
@idasync
@tool_timeout(120.0)
def survey_binary(
    detail_level: Annotated[str, "fast (default, compact) or full; minimal/standard are aliases"] = "fast",
) -> dict:
    """Prefer analysis_run(mode="triage", ...) for canonical triage.
    WHEN: first call on a new binary, before drilling into functions.
    RETURNS: {metadata, statistics, segments, entrypoints, interesting_functions[{addr,name,size,xref_count,callee_count,reasons[]}], interesting_strings[{addr,string,xref_count,kind?}], imports_by_category{category: {count, items}}, call_graph_summary? (full only), _note?}.
    LIMITS: fast = top 10 functions/strings, 5 imports per category; full = top 25, 20 per category plus call graph roots. Thunks, FLIRT library code, import stubs and CRT helpers are excluded; loader/import-name/junk strings are dropped. Scores at most 10000 functions and 5000 strings (_note when truncated).
    NEXT: analysis_run(mode="function") on listed functions; graph_query for callers/callees."""
    import idautils

    level = _LEVELS.get(str(detail_level).strip().lower())
    if level is None:
        raise IDAError(f"Unknown detail_level {detail_level!r}; allowed: fast, full (aliases: minimal, standard)")
    limits = _LIMITS[level]

    all_func_eas = list(idautils.Functions())
    truncated = len(all_func_eas) > _MAX_FUNC_ITER
    func_eas = all_func_eas[:_MAX_FUNC_ITER]

    strings = _get_strings_cache()
    segments = _build_segments()
    entrypoints = _build_entrypoints()
    exported = {int(row["addr"], 16) for row in entrypoints if "ordinal" in row}

    stats = _build_statistics(func_eas, len(strings), len(segments))
    stats["total_functions"] = len(all_func_eas)
    stats["functions_scored"] = len(func_eas)
    stats["total_entrypoints"] = len(entrypoints)

    imports = [(ea, name, module, classify_import(name, module)) for ea, name, module in _collect_imports()]
    import_names = {n.lower() for _ea, name, module, _cat in imports for n in (name, module, f"{module}.dll") if n}
    interesting_strings, string_eas = _build_interesting_strings(import_names, limits["top"])

    scanner = _FunctionScanner({ea: cat for ea, _name, _module, cat in imports}, string_eas)
    features = {ea: feat for ea in func_eas if (feat := scanner.scan(ea))}

    result: dict = {
        "metadata": _build_metadata(),
        "statistics": stats,
        "segments": segments,
        "entrypoints": entrypoints[: limits["entrypoints"]],
        "interesting_functions": _build_interesting_functions(features, scanner, exported, limits["top"]),
        "interesting_strings": interesting_strings,
        "imports_by_category": _build_imports_by_category(imports, limits["per_category"]),
    }
    if level == "full":
        result["call_graph_summary"] = _build_call_graph_summary(features, limits["roots"])

    if truncated:
        result["_note"] = (
            f"Binary has {len(all_func_eas)} functions; "
            f"function scoring was limited to the first {_MAX_FUNC_ITER}."
        )

    return result
