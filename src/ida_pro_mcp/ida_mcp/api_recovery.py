"""Switch-table, patch, RTTI/class, FLIRT/TIL, and similarity enumeration (Phase C module).

Pure collectors called on the IDA main thread via ``entity_query``'s
existing ``@idasync`` path. Rows carry an ``"addr"`` hex-string key so the
filter/sort/paginate pipeline applies unchanged.
"""

from __future__ import annotations

from itertools import islice

import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_idp
import ida_loader
import ida_name
import ida_nalt
import ida_segment
import ida_typeinf
import ida_ua
import ida_xref
import idaapi
import idautils

from ida_pro_mcp.vnext.contracts import ErrorCode, VNextError

from . import compat
from .rpc import tool, unsafe
from .sync import idasync
from .utils import normalize_dict_list, parse_address, resolve_address_or_name


def _mnemonics(start_ea: int, cap: int) -> list[str]:
    """Mnemonic per instruction head, capped so one giant function cannot stall the scan."""
    mnems: list[str] = []
    for item_ea in islice(idautils.FuncItems(start_ea), cap):
        try:
            mnem = ida_ua.print_insn_mnem(int(item_ea))
        except Exception:
            continue
        if mnem:
            mnems.append(str(mnem))
    return mnems


def collect_switches(func_eas: list[int] | None = None) -> list[dict]:
    """Enumerate IDA switch tables via get_switch_info + calc_switch_cases."""
    if func_eas is None:
        func_eas = [int(ea) for ea in idautils.Functions()]
    rows: list[dict] = []
    for func_ea in func_eas:
        func = compat.get_func(int(func_ea))
        if func is None:
            continue
        func_name = ida_funcs.get_func_name(int(func_ea)) or ""
        ea = int(func.start_ea)
        end_ea = int(compat.get_func_end_ea(func) or func.end_ea)
        while ea != idaapi.BADADDR and ea < end_ea:
            si = ida_nalt.switch_info_t()
            try:
                has_switch = ida_nalt.get_switch_info(si, ea)
            except Exception:
                has_switch = None
            if has_switch is None or (isinstance(has_switch, int) and has_switch <= 0):
                ea = ida_bytes.next_head(ea, end_ea)
                continue
            try:
                results = ida_xref.calc_switch_cases(ea, si)
            except Exception:
                results = None
            if results is None:
                ea = ida_bytes.next_head(ea, end_ea)
                continue
            cases: list[dict] = []
            try:
                ncases = len(results.cases)
            except Exception:
                ncases = 0
            for idx in range(ncases):
                try:
                    cur = results.cases[idx]
                    values = [int(cur[cidx]) for cidx in range(len(cur))]
                    target = int(results.targets[idx])
                except Exception:
                    continue
                cases.append({"values": values, "target": hex(target)})
            default = int(si.defjump)
            rows.append(
                {
                    "addr": hex(ea),
                    "func": func_name,
                    "jumptable": hex(int(si.jumps)),
                    "ncases": len(cases),
                    "default": None if default == idaapi.BADADDR else hex(default),
                    "cases": cases,
                }
            )
            ea = ida_bytes.next_head(ea, end_ea)
    return rows


def collect_patches() -> list[dict]:
    """Enumerate patched bytes, coalescing contiguous runs."""
    found: list[tuple[int, int, int]] = []

    def _visit(ea: int, fpos: int, org_val: int, patch_val: int) -> int:
        found.append((int(ea), int(org_val) & 0xFF, int(patch_val) & 0xFF))
        return 0

    ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, _visit)
    rows: list[dict] = []
    for ea, org, new in sorted(found):
        if rows and ea == int(rows[-1]["_end"]):
            rows[-1]["_end"] = ea + 1
            rows[-1]["original"] += f"{org:02x}"
            rows[-1]["patched"] += f"{new:02x}"
            rows[-1]["size"] += 1
            continue
        rows.append(
            {
                "addr": hex(ea),
                "file_offset": int(ida_loader.get_fileregion_offset(ea)),
                "size": 1,
                "original": f"{org:02x}",
                "patched": f"{new:02x}",
                "_end": ea + 1,
            }
        )
    for row in rows:
        del row["_end"]
    return rows


def patch_diff_text() -> str:
    """Render patched bytes in IDA .dif text format."""
    try:
        filename = ida_nalt.get_root_filename() or "input"
    except Exception:
        filename = "input"
    lines = [filename]
    for row in collect_patches():
        addr = int(str(row["addr"]), 16)
        file_offset = int(row["file_offset"])
        base = file_offset if file_offset >= 0 else addr
        orig = str(row["original"])
        new = str(row["patched"])
        orig_pairs = " ".join(orig[i : i + 2] for i in range(0, len(orig), 2))
        new_pairs = " ".join(new[i : i + 2] for i in range(0, len(new), 2))
        lines.append(f"{base:08X}: {orig_pairs} {new_pairs}")
    return "\n".join(lines) + "\n"


def _is_64bit() -> bool:
    try:
        return bool(compat.inf_is_64bit())
    except Exception:
        return True


def _mapped(ea: int) -> bool:
    try:
        return bool(ida_bytes.is_mapped(int(ea)))
    except Exception:
        try:
            return idaapi.getseg(int(ea)) is not None
        except Exception:
            return False


def _read_ptr(ea: int, is64: bool) -> int | None:
    try:
        return int(idaapi.get_qword(ea) if is64 else idaapi.get_dword(ea))
    except Exception:
        return None


def _data_ranges() -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = compat.get_segment_info(seg_ea)
        if seg is None:
            continue
        try:
            if compat.get_segment_perm(seg) & ida_segment.SEGPERM_EXEC:
                continue
        except Exception:
            continue
        ranges.append((int(seg.start_ea), int(seg.end_ea)))
    return ranges


def _slot_name(ea: int) -> str:
    try:
        name = ida_funcs.get_func_name(int(ea)) or ""
    except Exception:
        name = ""
    if name:
        return str(name)
    try:
        label = ida_name.get_name(int(ea)) or ""
    except Exception:
        label = ""
    return str(label) if not isinstance(label, str) else label


def _is_code_target(ea: int) -> bool:
    func = compat.get_func(int(ea))
    if func is not None:
        return True
    try:
        flags = ida_bytes.get_flags(int(ea))
        return bool(idaapi.is_code(flags))
    except Exception:
        return False


def _collect_slots(vtable_ea: int, is64: bool, limit: int = 256) -> list[dict] | None:
    """Read vtable slots until the first pointer that is not to code."""
    step = 8 if is64 else 4
    slots: list[dict] = []
    for index in range(limit):
        ptr = _read_ptr(int(vtable_ea) + index * step, is64)
        if ptr is None or not _mapped(ptr):
            break
        if not slots and compat.get_func(ptr) is None:
            return None
        if not _is_code_target(ptr):
            break
        slots.append({"index": index, "addr": hex(ptr), "name": _slot_name(ptr)})
    return slots or None


def _demangled(raw: str) -> str:
    for mode in (0, ida_name.MNG_LONG_FORM):
        try:
            out = ida_name.demangle_name(raw, mode)
        except Exception:
            continue
        if isinstance(out, str) and out:
            return out
    return raw


def _string_at(ea: int) -> str:
    try:
        raw = ida_bytes.get_strlit_contents(int(ea), 256, ida_nalt.STRTYPE_C)
    except Exception:
        return ""
    if not raw:
        return ""
    try:
        return bytes(raw).decode("utf-8", "replace").split("\x00")[0]
    except Exception:
        return ""


def _read_u32(ea: int) -> int | None:
    try:
        return int(idaapi.get_dword(int(ea))) & 0xFFFFFFFF
    except Exception:
        return None


def _image_base() -> int:
    try:
        return int(idaapi.get_imagebase())
    except Exception:
        return 0

def _msvc_td_name(td_ea: int) -> str:
    """TypeDescriptor name is inline at +16 (x64: vftable, spare, name)."""
    raw = _string_at(int(td_ea) + 16)
    if not raw.startswith(".?A"):
        probe = _string_at(int(td_ea) + 8)
        raw = probe if probe.startswith(".?A") else raw
    if not raw.startswith(".?A"):
        return ""
    # Raw `.?AV…` strings do not demangle directly; demangle the ??_R0 symbol
    # name IDA attached to the TypeDescriptor instead.
    try:
        sym = ida_name.get_name(int(td_ea)) or ""
    except Exception:
        sym = ""
    if sym:
        out = _demangled(str(sym))
        if out != sym:
            return out
    return raw


def _msvc_bases(chd_ea: int, is64: bool) -> list[str]:
    """ClassHierarchyDescriptor: signature, attributes, numBaseClasses, pBaseClassArray."""
    bases: list[str] = []
    count = _read_u32(int(chd_ea) + 8)
    array_field = _read_u32(int(chd_ea) + 12)
    if count is None or array_field is None:
        return bases
    if count <= 0 or count > 64:
        return bases
    array_ea = (_image_base() + array_field) if is64 else array_field
    if not _mapped(array_ea):
        return bases
    for i in range(count):
        entry = _read_u32(int(array_ea) + i * 4)
        if entry is None:
            break
        # BaseClassDescriptor: pTypeDescriptor at +0 (RVA on x64).
        bcd_ea = (_image_base() + entry) if is64 else entry
        if not _mapped(bcd_ea):
            break
        td_field = _read_u32(int(bcd_ea))
        if td_field is None:
            continue
        td_ea = (_image_base() + td_field) if is64 else td_field
        if not _mapped(td_ea):
            continue
        label = _msvc_td_name(int(td_ea))
        if label:
            bases.append(label)
    return bases


def _is_col_candidate(col_ea: int, is64: bool) -> tuple[int, int] | None:
    """Validate an MSVC CompleteObjectLocator; return (td_ea, chd_ea)."""
    col_ea = int(col_ea)
    if not is64:
        fields = [_read_ptr(col_ea + i * 4, False) for i in range(5)]
        if any(v is None for v in fields):
            return None
        sig = int(fields[0] or 0) & 0xFFFFFFFF
        if sig not in (0, 1):
            return None
        td_ea, chd_ea = int(fields[3] or 0), int(fields[4] or 0)
        if not _mapped(td_ea) or not _msvc_td_name(td_ea):
            return None
        if not _mapped(chd_ea):
            return None
        return (td_ea, chd_ea)
    dwords = [_read_u32(col_ea + i * 4) for i in range(6)]
    if any(v is None for v in dwords):
        return None
    if int(dwords[0] or 0) not in (0, 1):
        return None
    base = _image_base()
    td_ea, chd_ea = base + int(dwords[3] or 0), base + int(dwords[4] or 0)
    if not _mapped(td_ea) or not _msvc_td_name(td_ea):
        # Absolute-pointer form once IDA resolves the RVAs.
        td_alt = _read_ptr(col_ea + 12, True)
        chd_alt = _read_ptr(col_ea + 16, True)
        if td_alt is None or chd_alt is None:
            return None
        if not _mapped(td_alt) or not _msvc_td_name(int(td_alt)):
            return None
        if not _mapped(chd_alt):
            return None
        return (int(td_alt), int(chd_alt))
    if not _mapped(chd_ea):
        return None
    # x64 self-RVA check: last dword is the COL's own RVA.
    if int(dwords[5] or 0) != (col_ea - base) & 0xFFFFFFFF:
        return None
    return (td_ea, chd_ea)


def _collect_msvc(rows: list[dict], is64: bool) -> None:
    seen_vtables: set[int] = {int(r["addr"], 16) for r in rows}
    step = 8 if is64 else 4
    cols: set[int] = set()
    names_cache: list[tuple[int, str]] = []
    try:
        names_cache = [(int(ea), str(nm or "")) for ea, nm in idautils.Names()]
    except Exception:
        names_cache = []
    for ea, label in names_cache:
        if "CompleteObjectLocator" in label or label.startswith("??_R4"):
            cols.add(int(ea))
    col_size = 24 if is64 else 20
    # ponytail: O(n) dword scan of data segments per query; index COLs if large PEs get slow.
    for start, end in _data_ranges():
        ea = int(start)
        while ea + col_size <= int(end):
            if _is_col_candidate(ea, is64) is not None:
                cols.add(ea)
                ea += col_size
            else:
                ea += 4
    # The vtable starts right after a slot holding the COL pointer
    # (one COL may back several vtables via separate pointer slots).
    vtables_by_col: dict[int, list[int]] = {}
    if cols:
        for start, end in _data_ranges():
            ea = int(start)
            while ea + step <= int(end):
                ptr = _read_ptr(ea, is64)
                if ptr is not None and int(ptr) in cols:
                    vtables_by_col.setdefault(int(ptr), []).append(ea + step)
                ea += step
    for col_ea in sorted(cols):
        hit = _is_col_candidate(col_ea, is64)
        if hit is None:
            continue
        td_ea, chd_ea = hit
        name = _msvc_td_name(int(td_ea))
        if not name:
            continue
        for vtable_ea in vtables_by_col.get(int(col_ea), []):
            if vtable_ea in seen_vtables:
                continue
            first = _read_ptr(vtable_ea, is64)
            if first is None or compat.get_func(int(first)) is None:
                continue
            slots = _collect_slots(vtable_ea, is64)
            if not slots:
                continue
            seen_vtables.add(vtable_ea)
            rows.append(
                {
                    "addr": hex(vtable_ea),
                    "name": name,
                    "abi": "msvc",
                    "bases": _msvc_bases(chd_ea, is64),
                    "slots": slots,
                }
            )


def _itanium_class_name(ti_ea: int) -> str:
    # __class_type_info layout is vtable-then-name at +step.
    step = 8 if _is_64bit() else 4
    name_ptr = _read_ptr(int(ti_ea) + step, step == 8)
    if name_ptr is None or not _mapped(name_ptr):
        return ""
    raw = _string_at(int(name_ptr))
    if not raw:
        return ""
    return _demangled(raw) or raw


def _itanium_bases(ti_ea: int, is64: bool) -> list[str]:
    step = 8 if is64 else 4
    vtable_ptr = _read_ptr(int(ti_ea), is64)
    if vtable_ptr is None:
        return []
    try:
        vtable_name = _slot_name(int(vtable_ptr))
    except Exception:
        vtable_name = ""
    bases: list[str] = []
    if "__vmi_class_type_info" in str(vtable_name):
        # flags @2*step, base_count @2*step+4, entries @2*step+8, stride 2*step.
        count = _read_u32(int(ti_ea) + 2 * step + 4)
        if count is None or count <= 0 or count > 64:
            return bases
        for i in range(count):
            base_ti = _read_ptr(int(ti_ea) + 2 * step + 8 + i * 2 * step, is64)
            if base_ti is None or not _mapped(base_ti):
                break
            label = _itanium_class_name(int(base_ti))
            if label:
                bases.append(label)
    elif "__si_class_type_info" in str(vtable_name):
        base_ti = _read_ptr(int(ti_ea) + 2 * step, is64)
        if base_ti is not None and _mapped(base_ti):
            label = _itanium_class_name(int(base_ti))
            if label:
                bases.append(label)
    return bases


def _collect_itanium(rows: list[dict], is64: bool) -> None:
    seen_vtables: set[int] = {int(r["addr"], 16) for r in rows}
    step = 8 if is64 else 4
    ti_addrs: dict[int, str] = {}
    vtables: list[tuple[int, str]] = []
    try:
        names_cache = [(int(ea), str(nm or "")) for ea, nm in idautils.Names()]
    except Exception:
        names_cache = []
    for ea, label in names_cache:
        if label.startswith("_ZTI"):
            ti_addrs[int(ea)] = label
        elif label.startswith("_ZTV"):
            vtables.append((int(ea), label))
    for vtable_ea, label in sorted(vtables):
        if vtable_ea in seen_vtables:
            continue
        # Itanium vtable layout: [offset-to-top, typeinfo ptr, slots...].
        ti_ptr = _read_ptr(int(vtable_ea) + step, is64)
        if ti_ptr is None or not _mapped(ti_ptr):
            continue
        try:
            offset_to_top = int(idaapi.get_dword(int(vtable_ea)))
        except Exception:
            continue
        if offset_to_top != 0:
            continue
        name = _itanium_class_name(int(ti_ptr))
        if not name:
            short = label[4:].split(" ")[0]
            name = _demangled("_ZTI" + short) or label
        first = _read_ptr(int(vtable_ea) + 2 * step, is64)
        if first is None or compat.get_func(int(first)) is None:
            continue
        slots = _collect_slots(int(vtable_ea) + 2 * step, is64)
        if not slots:
            continue
        seen_vtables.add(vtable_ea)
        rows.append(
            {
                "addr": hex(int(vtable_ea) + 2 * step),
                "name": name,
                "abi": "itanium",
                "bases": _itanium_bases(int(ti_ptr), is64),
                "slots": slots,
            }
        )


def collect_classes() -> list[dict]:
    """Recover C++ classes/vtables from MSVC RTTI and Itanium ABI metadata."""
    is64 = _is_64bit()
    rows: list[dict] = []
    try:
        _collect_itanium(rows, is64)
    except Exception:
        pass
    try:
        _collect_msvc(rows, is64)
    except Exception:
        pass
    rows.sort(key=lambda row: int(str(row.get("addr", "0x0")), 16))
    return rows


def _processor_subdir(base: str) -> str:
    """Resolve the current processor's subdir of an IDA resource dir (sig/til)."""
    candidates: list[str] = []
    for getter in (ida_idp.get_idp_name, idaapi.inf_get_procname):
        try:
            value = str(getter() or "").strip().lower()
        except Exception:
            continue
        if value and value not in candidates:
            candidates.append(value)
    for candidate in candidates:
        sub = os.path.join(base, candidate)
        try:
            if os.path.isdir(sub):
                return sub
        except Exception:
            continue
    return base


def _sig_key(name: str) -> str:
    stem = os.path.basename(str(name or "").strip())
    if stem.lower().endswith(".sig"):
        stem = stem[:-4]
    return stem.lower()


def _applied_sig_names() -> set[str]:
    """Short names of planned/applied FLIRT signatures (extension-insensitive)."""
    try:
        qty = int(ida_funcs.get_idasgn_qty())
    except Exception:
        return set()
    planned = getattr(ida_funcs, "IDASGN_PLANNED", 4)
    names: set[str] = set()
    for index in range(max(0, qty)):
        desc = None
        try:
            desc = ida_funcs.get_idasgn_desc_with_matches(index)
        except Exception:
            desc = None
        if desc is None:
            try:
                desc = ida_funcs.get_idasgn_desc(index)
            except Exception:
                continue
        if not desc:
            continue
        try:
            state = int(ida_funcs.calc_idasgn_state(index))
        except Exception:
            state = -1
        if state == planned:
            continue
        names.add(_sig_key(str(desc[0])))
    return names


def _loaded_til_names() -> set[str]:
    """Names of TILs in the local base chain (case-insensitive)."""
    try:
        til = ida_typeinf.get_idati()
    except Exception:
        return set()
    if not til:
        return set()
    names: set[str] = set()
    try:
        count = int(til.nbases)
    except Exception:
        return set()
    for index in range(max(0, count)):
        try:
            base = til.base(index)
            names.add(str(base.name or "").strip().lower())
        except Exception:
            continue
    return names


def collect_signature_files() -> list[dict]:
    """List FLIRT .sig files for the current processor with applied flags."""
    try:
        directory = _processor_subdir(idaapi.idadir("sig"))
        files = sorted(f for f in os.listdir(directory) if f.lower().endswith(".sig"))
    except Exception:
        return []
    applied = _applied_sig_names()
    rows: list[dict] = []
    for filename in files:
        stem = os.path.splitext(filename)[0]
        try:
            description = str(ida_funcs.get_idasgn_title(stem) or "")
        except Exception:
            description = ""
        rows.append(
            {
                "addr": "0x0",
                "name": stem,
                "path": os.path.join(directory, filename),
                "description": description,
                "applied": _sig_key(stem) in applied,
            }
        )
    return rows


def collect_type_libraries() -> list[dict]:
    """List .til files for the current processor with loaded flags."""
    try:
        directory = _processor_subdir(idaapi.idadir("til"))
        files = sorted(f for f in os.listdir(directory) if f.lower().endswith(".til"))
    except Exception:
        return []
    loaded = _loaded_til_names()
    rows: list[dict] = []
    for filename in files:
        stem = os.path.splitext(filename)[0]
        try:
            header = ida_typeinf.load_til_header(directory, stem)
            description = str(header.desc or "") if header else ""
        except Exception:
            description = ""
        rows.append(
            {
                "addr": "0x0",
                "name": stem,
                "path": os.path.join(directory, filename),
                "description": description,
                "loaded": stem.lower() in loaded,
            }
        )
    return rows


def _trigrams(mnems: list[str]) -> set[tuple[str, ...]]:
    return {tuple(mnems[i : i + 3]) for i in range(len(mnems) - 2)} if len(mnems) >= 3 else set()


def similar_functions(ea: int, limit: int = 20, min_score: float = 0.3) -> list[dict]:
    """Rank functions by mnemonic 3-gram Jaccard against the query function.

    Per-function cost is bounded at 2000 instructions; the query function itself
    always scores 1.0 and sorts first.
    """
    # ponytail: O(n) scan per query, MinHash/LSH index if slow on large IDBs
    query = compat.get_func(int(ea))
    if query is None:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"Not a function: {int(ea):#x}")
    cap = 2000
    query_start = int(query.start_ea)
    query_mnems = _mnemonics(query_start, cap)
    query_grams = _trigrams(query_mnems)
    query_count = len(query_mnems)
    rows: list[dict] = []
    for cand_ea in idautils.Functions():
        cand_ea = int(cand_ea)
        if compat.get_func(cand_ea) is None:
            continue
        mnems = query_mnems if cand_ea == query_start else _mnemonics(cand_ea, cap)
        count = len(mnems)
        if cand_ea == query_start:
            rows.append({"addr": hex(cand_ea), "name": ida_funcs.get_func_name(cand_ea) or "", "score": 1.0, "insn_count": count})
            continue
        if not query_count or not count or count < query_count * 0.5 or count > query_count * 2:
            continue
        other = _trigrams(mnems)
        if not query_grams and not other:
            score = 1.0 if mnems == query_mnems else 0.0
        elif not query_grams or not other:
            score = 0.0
        else:
            score = len(query_grams & other) / len(query_grams | other)
        if score >= float(min_score):
            rows.append({"addr": hex(cand_ea), "name": ida_funcs.get_func_name(cand_ea) or "", "score": score, "insn_count": count})
    rows.sort(key=lambda row: row["score"], reverse=True)
    return rows[: max(0, int(limit))]


def apply_flirt(name: str) -> dict:
    """Plan a FLIRT signature file, wait for analysis, report renamed count."""
    short = os.path.basename(str(name or "").strip())
    if not short:
        raise VNextError(ErrorCode.INVALID_OPERATION, "FLIRT apply is missing a signature name")
    before = {ea: ida_funcs.get_func_name(ea) for ea in idautils.Functions()}
    planned = 0
    try:
        planned = int(ida_funcs.plan_to_apply_idasgn(short))
    except Exception:
        planned = 0
    if not planned and not short.lower().endswith(".sig"):
        try:
            planned = int(ida_funcs.plan_to_apply_idasgn(short + ".sig"))
        except Exception:
            planned = 0
    if not planned:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"Unknown FLIRT signature: {name}")
    ida_auto.auto_wait()
    renamed = 0
    try:
        for ea, old in before.items():
            try:
                if ida_funcs.get_func_name(ea) != old:
                    renamed += 1
            except Exception:
                continue
    except Exception:
        return {"name": short}
    return {"name": short, "renamed": renamed}


def load_til(name: str) -> dict:
    """Load a type library into the database; raises INVALID_OPERATION on failure."""
    short = os.path.basename(str(name or "").strip())
    if short.lower().endswith(".til"):
        short = short[:-4]
    if not short:
        raise VNextError(ErrorCode.INVALID_OPERATION, "TIL load is missing a library name")
    try:
        result = int(ida_typeinf.add_til(short, ida_typeinf.ADDTIL_DEFAULT))
    except Exception as exc:
        raise VNextError(ErrorCode.INVALID_OPERATION, f"Failed to load type library {short!r}: {exc}") from exc
    if result not in (ida_typeinf.ADDTIL_OK, ida_typeinf.ADDTIL_COMP):
        raise VNextError(ErrorCode.INVALID_OPERATION, f"Failed to load type library {short!r} (result {result})")
    return {"name": short, "loaded": True}



@tool
@idasync
@unsafe
def apply_flirt_signature(
    items: Annotated[list[dict[str, Any]] | dict[str, Any], "FLIRT signature applications ({name})"],
) -> list[dict]:
    """Prefer mutation_preview(kind="apply_flirt", ...).

    WHEN: stage a FLIRT signature application through the transaction flow.
    RETURNS: [{name, renamed, ok, error}] per item.
    LIMITS: unknown signature names return error entries; apply waits for auto-analysis."""
    results = []
    for item in normalize_dict_list(items, lambda s: {"name": s}):
        entry = str(item.get("name", "") or "")
        try:
            outcome = apply_flirt(entry)
            results.append({"name": entry, "renamed": outcome.get("renamed", 0), "ok": True, "error": None})
        except VNextError as exc:
            results.append({"name": entry, "ok": False, "error": str(exc)})
        except Exception as exc:
            results.append({"name": entry, "ok": False, "error": str(exc)})
    return results


@tool
@idasync
@unsafe
def load_type_library(
    items: Annotated[list[dict[str, Any]] | dict[str, Any], "Type library loads ({name})"],
) -> list[dict]:
    """Prefer mutation_preview(kind="load_til", ...).

    WHEN: stage a type-library load through the transaction flow.
    RETURNS: [{name, loaded, ok, error}] per item.
    LIMITS: unknown or incompatible library names return error entries."""
    results = []
    for item in normalize_dict_list(items, lambda s: {"name": s}):
        entry = str(item.get("name", "") or "")
        try:
            load_til(entry)
            results.append({"name": entry, "loaded": True, "ok": True, "error": None})
        except VNextError as exc:
            results.append({"name": entry, "loaded": False, "ok": False, "error": str(exc)})
        except Exception as exc:
            results.append({"name": entry, "loaded": False, "ok": False, "error": str(exc)})
    return results


def resolve_switch_targets(query: dict[str, Any]) -> list[int] | None:
    """Resolve entity_query targets to function start eas, or None for all."""
    raw = query.get("targets")
    if raw is None:
        return None
    items = raw if isinstance(raw, list) else [raw]
    eas: list[int] = []
    for item in items:
        if isinstance(item, dict):
            item = item.get("addr", "")
        try:
            ea = resolve_address_or_name(item)
        except Exception:
            continue
        func = compat.get_func(ea)
        if func is None:
            try:
                ea = parse_address(item)
            except Exception:
                continue
            func = compat.get_func(ea)
        if func is not None:
            eas.append(int(func.start_ea))
    return eas
