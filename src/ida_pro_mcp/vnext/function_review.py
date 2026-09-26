"""Hex-Rays function-review helpers with no IDA imports.

The in-IDA context menu uses these to format analysis_run evidence, build a
Cursor/Claude prompt, and stage mutation_preview operations. Keeping this
module IDA-free lets the portable suite cover the extra feature without a
live database.
"""

from __future__ import annotations

import re
from typing import Any

_HEXRAYS_LVAR_RE = re.compile(r"\b(?:[av]\d+|arg\d+)\b")
_MAX_DISPLAY_DECOMPILE_LINES = 80
_MAX_PROMPT_DECOMPILE_LINES = 100


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            items.append(item.strip())
        elif isinstance(item, dict):
            text = item.get("name") or item.get("value") or item.get("addr")
            if text:
                items.append(str(text))
    return items


def _decompile_excerpt(analysis: dict[str, Any], *, limit: int) -> str:
    code = analysis.get("decompiled")
    if not isinstance(code, str) or not code.strip():
        return ""
    lines = code.splitlines()
    excerpt = "\n".join(lines[:limit])
    extra = len(lines) - limit
    if extra > 0:
        excerpt += f"\n/* … {extra} more lines truncated … */"
    return excerpt


def lvar_names_from_decompiled(code: str | None) -> list[str]:
    """Return unique Hex-Rays-style local names found in pseudocode."""
    if not code:
        return []
    seen: set[str] = set()
    names: list[str] = []
    for match in _HEXRAYS_LVAR_RE.finditer(code):
        name = match.group(0)
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def local_rename_rows(analysis: dict[str, Any]) -> list[dict[str, str]]:
    """Prefer decompiler locals; fall back to names parsed from pseudocode."""
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in analysis.get("locals") or []:
        if isinstance(item, str):
            name = item.strip()
            is_arg = False
        elif isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            is_arg = bool(item.get("is_arg"))
        else:
            continue
        if not name or name in seen:
            continue
        seen.add(name)
        rows.append({"name": name, "is_arg": "1" if is_arg else "0", "new": ""})
    if rows:
        return rows
    for name in lvar_names_from_decompiled(analysis.get("decompiled") if isinstance(analysis.get("decompiled"), str) else None):
        rows.append({"name": name, "is_arg": "0", "new": ""})
    return rows


def format_analysis_summary(analysis: dict[str, Any]) -> str:
    """Human-readable evidence dump for the review dialog."""
    addr = str(analysis.get("addr") or "")
    name = str(analysis.get("name") or "")
    prototype = str(analysis.get("prototype") or "")
    error = analysis.get("error")
    lines = [
        f"Address: {addr}" if addr else "Address: (unknown)",
        f"Name: {name}" if name else "Name: (unnamed)",
    ]
    if prototype:
        lines.append(f"Prototype: {prototype}")
    size = analysis.get("size")
    if isinstance(size, int):
        lines.append(f"Size: {size} bytes")
    blocks = analysis.get("basic_blocks") or {}
    if isinstance(blocks, dict) and blocks:
        count = blocks.get("count")
        complexity = blocks.get("cyclomatic_complexity")
        parts = []
        if count is not None:
            parts.append(f"{count} blocks")
        if complexity is not None:
            parts.append(f"complexity {complexity}")
        if parts:
            lines.append("Control flow: " + ", ".join(parts))
    if error:
        lines.append(f"Error: {error}")

    strings = _as_str_list(analysis.get("strings"))
    if strings:
        lines.append("Strings: " + ", ".join(strings[:10]))
    callees = _as_str_list(analysis.get("callees"))
    if callees:
        lines.append("Callees: " + ", ".join(callees[:12]))
    callers = _as_str_list(analysis.get("callers"))
    if callers:
        lines.append("Callers: " + ", ".join(callers[:12]))
    constants = analysis.get("constants") or []
    const_text: list[str] = []
    if isinstance(constants, list):
        for item in constants[:8]:
            if isinstance(item, dict) and item.get("value") is not None:
                const_text.append(hex(item["value"]) if isinstance(item["value"], int) else str(item["value"]))
            elif isinstance(item, int):
                const_text.append(hex(item))
    if const_text:
        lines.append("Constants: " + ", ".join(const_text))

    locals_ = local_rename_rows(analysis)
    if locals_:
        names = [row["name"] for row in locals_]
        lines.append("Locals: " + ", ".join(names[:20]))

    excerpt = _decompile_excerpt(analysis, limit=_MAX_DISPLAY_DECOMPILE_LINES)
    if excerpt:
        lines.append("")
        lines.append("Decompiled:")
        lines.append(excerpt)
    return "\n".join(lines)


def build_cursor_prompt(analysis: dict[str, Any], *, database: str = "") -> str:
    """Build a paste-ready MCP agent prompt for the current function."""
    addr = str(analysis.get("addr") or "").strip() or "<unknown>"
    name = str(analysis.get("name") or "").strip() or "<unnamed>"
    database_line = f"Database session: `{database}`.\n" if database else ""
    excerpt = _decompile_excerpt(analysis, limit=_MAX_PROMPT_DECOMPILE_LINES)
    strings = ", ".join(_as_str_list(analysis.get("strings"))[:10]) or "(none)"
    callees = ", ".join(_as_str_list(analysis.get("callees"))[:12]) or "(none)"
    callers = ", ".join(_as_str_list(analysis.get("callers"))[:12]) or "(none)"
    locals_ = ", ".join(row["name"] for row in local_rename_rows(analysis)[:20]) or "(none)"
    decompile_block = excerpt if excerpt else "(decompilation unavailable)"
    return (
        f"{database_line}"
        f"Analyze function `{name}` at {addr} in the current IDA database.\n"
        "\n"
        "This evidence was already collected with analysis_run(mode=\"function\"). "
        "Do not repeat that call unless you need assembly or a wider neighborhood.\n"
        "\n"
        "Workflow:\n"
        "1. Use graph_query / dataflow_trace / type_query only where this evidence is not enough.\n"
        "2. Propose a better function name, a concise comment, and local-variable names.\n"
        "3. Stage every IDB change with mutation_preview. Do not mutation_commit until I approve.\n"
        "4. Cite addresses and label uncertainty.\n"
        "\n"
        f"Current name: {name}\n"
        f"Address: {addr}\n"
        f"Prototype: {analysis.get('prototype') or '(unknown)'}\n"
        f"Strings: {strings}\n"
        f"Callees: {callees}\n"
        f"Callers: {callers}\n"
        f"Locals: {locals_}\n"
        "\n"
        "Decompiled:\n"
        f"{decompile_block}\n"
    )


def selected_local_renames(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Keep rows whose new name is non-empty and different from the original."""
    selected: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        old_name = str(row.get("name") or row.get("old") or "").strip()
        new_name = str(row.get("new") or row.get("new_name") or "").strip()
        if not old_name or not new_name or old_name == new_name or old_name in seen:
            continue
        seen.add(old_name)
        selected.append({"old": old_name, "new": new_name})
    return selected


def build_mutation_operations(
    *,
    addr: str,
    current_name: str = "",
    new_name: str = "",
    comment: str | None = "",
    current_comment: str = "",
    local_renames: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Build canonical mutation_preview operations for the review dialog."""
    from .contracts import ErrorCode, VNextError

    operations: list[dict[str, Any]] = []
    target = str(addr or "").strip()
    if not target:
        raise VNextError(ErrorCode.INVALID_OPERATION, "Mutation address cannot be empty")

    rename_args: dict[str, Any] = {}
    cleaned_new = str(new_name or "").strip()
    cleaned_current = str(current_name or "").strip()
    if cleaned_new and cleaned_new != cleaned_current:
        rename_args["func"] = [{"addr": target, "name": cleaned_new}]

    locals_payload = []
    for item in local_renames or []:
        old_name = str(item.get("old") or item.get("name") or "").strip()
        new_local = str(item.get("new") or item.get("new_name") or "").strip()
        if not old_name or not new_local or old_name == new_local:
            continue
        locals_payload.append({"func_addr": target, "old": old_name, "new": new_local})
    if locals_payload:
        rename_args["local"] = locals_payload
    if rename_args:
        operations.append({"kind": "rename", **rename_args})

    if comment is not None and str(comment).strip() != str(current_comment or "").strip():
        operations.append({"kind": "comment", "addr": target, "comment": str(comment)})
    return operations


def attach_review_views(analysis: dict[str, Any], *, database: str = "") -> dict[str, Any]:
    """Copy analysis and add summary/prompt fields used by the dialog."""
    review = dict(analysis)
    review["summary"] = format_analysis_summary(review)
    review["prompt"] = build_cursor_prompt(review, database=database)
    review["local_rows"] = local_rename_rows(review)
    return review
