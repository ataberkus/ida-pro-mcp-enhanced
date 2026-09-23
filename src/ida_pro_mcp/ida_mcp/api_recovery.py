"""Switch-table and patch enumeration (Phase C base module).

Pure collectors called on the IDA main thread via ``entity_query``'s
existing ``@idasync`` path. Rows carry an ``"addr"`` hex-string key so the
filter/sort/paginate pipeline applies unchanged.

Remaining collectors (``collect_classes``, ``collect_signature_files``,
``collect_type_libraries``, ``similar_functions``, ``apply_flirt``,
``load_til``) are stubs until tasks C2-C4 fill them.
"""

from __future__ import annotations

from typing import Annotated, Any

import ida_bytes
import ida_funcs
import ida_loader
import ida_nalt
import ida_xref
import idaapi
import idautils

from ida_pro_mcp.vnext.contracts import ErrorCode, VNextError

from . import compat
from .rpc import tool, unsafe
from .sync import idasync
from .utils import parse_address, resolve_address_or_name


def _not_supported(what: str) -> VNextError:
    allowed = "switches, patches, classes, vtables, signatures, type_libraries"
    return VNextError(ErrorCode.NOT_SUPPORTED, f"{what} is not implemented yet. Allowed: {allowed}")


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
        import ida_nalt

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


def _stub_collect_classes() -> list[dict]:
    raise _not_supported("collect_classes")


def _stub_collect_signature_files() -> list[dict]:
    raise _not_supported("collect_signature_files")


def _stub_collect_type_libraries() -> list[dict]:
    raise _not_supported("collect_type_libraries")


def _stub_similar_functions(ea: int, limit: int, min_score: float) -> list[dict]:
    raise _not_supported("similar_functions")


def _stub_apply_flirt(name: str) -> dict:
    raise _not_supported("apply_flirt")


def _stub_load_til(name: str) -> dict:
    raise _not_supported("load_til")


# Canonical collector names reserved for C2-C4. The module-level aliases
# keep one public spelling so later tasks fill implementations in place.
collect_classes = _stub_collect_classes
collect_signature_files = _stub_collect_signature_files
collect_type_libraries = _stub_collect_type_libraries
similar_functions = _stub_similar_functions
apply_flirt = _stub_apply_flirt
load_til = _stub_load_til


@tool
@idasync
@unsafe
def apply_flirt_signature(
    items: Annotated[list[dict[str, Any]] | dict[str, Any], "FLIRT signature applications ({name})"],
) -> list[dict]:
    """Prefer mutation_preview(kind="apply_flirt", ...).

    WHEN: stage a FLIRT signature application through the transaction flow.
    RETURNS: [{name, ok, error}] per item.
    LIMITS: stub until C3 implements FLIRT apply; raises NOT_SUPPORTED."""
    raise _not_supported("apply_flirt_signature")


@tool
@idasync
@unsafe
def load_type_library(
    items: Annotated[list[dict[str, Any]] | dict[str, Any], "Type library loads ({name})"],
) -> list[dict]:
    """Prefer mutation_preview(kind="load_til", ...).

    WHEN: stage a type-library load through the transaction flow.
    RETURNS: [{name, ok, error}] per item.
    LIMITS: stub until C3 implements TIL loading; raises NOT_SUPPORTED."""
    raise _not_supported("load_type_library")


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
