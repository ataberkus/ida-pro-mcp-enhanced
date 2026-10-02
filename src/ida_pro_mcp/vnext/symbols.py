"""Pure symbol-text helpers (no IDA imports) for display names and address expressions."""

from __future__ import annotations

import difflib
import re

_OPERATOR_SYMBOLS = "<>=!+-*/%^&|~,"
_TRAILING_QUALIFIERS = re.compile(
    r"(?:\s*(?:const|volatile|noexcept|__ptr64|__restrict|&&|&|\[clone [^\]]*\]))+$"
)
_SPECIAL_PREFIX = re.compile(
    r"^((?:non-virtual |virtual |covariant return )?thunk to |vtable for |VTT for |"
    r"typeinfo for |typeinfo name for |construction vtable for .*?-in-|guard variable for |"
    r"reference temporary (?:#\d+ )?for |TLS init function for |TLS wrapper function for )(.*)$"
)
_OFFSET_EXPR = re.compile(r"^(.+?)\s*([+-])\s*(0[xX][0-9a-fA-F]+|[0-9a-fA-F]+)$")
_SEGMENT_EXPR = re.compile(r"^([^:\s]+):(?:0[xX])?([0-9a-fA-F]+)[hH]?$")
_BARE_HEX = re.compile(r"^([0-9a-fA-F]+)[hH]?$")


def _depths(text: str) -> list[int]:
    """Bracket depth per character; operator tokens (operator<, operator()) stay neutral."""
    out = [0] * len(text)
    depth = 0
    ticks = 0
    i, n = 0, len(text)
    while i < n:
        if (
            text.startswith("operator", i)
            and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"))
        ):
            j = i + 8
            if text[j : j + 2] in ("()", "[]"):
                j += 2
            else:
                while j < n and text[j] in _OPERATOR_SYMBOLS:
                    j += 1
            for k in range(i, j):
                out[k] = depth
            i = j
            continue
        ch = text[i]
        if ch in "<([{`":
            depth += 1
            ticks += ch == "`"
            out[i] = depth
        elif ch in ">)]}" or (ch == "'" and ticks):
            out[i] = depth
            depth = max(0, depth - 1)
            if ch == "'":
                ticks -= 1
        else:
            out[i] = depth
        i += 1
    return out


def _top_level_tokens(text: str) -> list[str]:
    depth = _depths(text)
    tokens, start = [], 0
    for i, ch in enumerate(text):
        if ch == " " and depth[i] == 0:
            if i > start:
                tokens.append(text[start:i])
            start = i + 1
    if start < len(text):
        tokens.append(text[start:])
    return tokens


def strip_signature(demangled: str) -> str:
    """Qualified name from a demangled symbol: drop return type, calling convention, params."""
    text = demangled.strip()
    special = _SPECIAL_PREFIX.match(text)
    if special:
        return special.group(1) + strip_signature(special.group(2))
    core = _TRAILING_QUALIFIERS.sub("", text)
    if core.endswith(")"):
        depth = 0
        for i in range(len(core) - 1, -1, -1):
            if core[i] == ")":
                depth += 1
            elif core[i] == "(":
                depth -= 1
                if depth == 0:
                    if i > 0:
                        text = core[:i].rstrip()
                    break
    tokens = _top_level_tokens(text)
    if not tokens:
        return demangled.strip()
    for idx, tok in enumerate(tokens):
        if tok == "operator" or tok.endswith("::operator"):
            return " ".join(tokens[idx:])
    return tokens[-1]


def collapse_templates(name: str, limit: int = 80) -> str:
    """Replace outermost template argument lists with `<…>` when ``name`` exceeds ``limit``."""
    if len(name) <= limit:
        return name
    depth = _depths(name)
    out, i, n = [], 0, len(name)
    while i < n:
        if name[i] == "<" and depth[i] == 1:
            j = i + 1
            while j < n and not (name[j] == ">" and depth[j] == 1):
                j += 1
            out.append("<…>")
            i = j + 1
            continue
        out.append(name[i])
        i += 1
    return "".join(out)


def pretty_symbol(demangled: str, limit: int = 80) -> str:
    return collapse_templates(strip_signature(demangled), limit)


def unqualified(name: str) -> str:
    """Last `::` component outside brackets (``ns::Foo<a::b>::bar`` -> ``bar``)."""
    depth = _depths(name)
    cut = 0
    for i in range(len(name) - 1):
        if name[i] == ":" and name[i + 1] == ":" and depth[i] == 0:
            cut = i + 2
    return name[cut:]


def parse_offset_expr(text: str) -> tuple[str, int] | None:
    """``name+0x10`` / ``name-16`` / ``name+1c`` -> (name, signed offset); decimal unless 0x or a-f."""
    m = _OFFSET_EXPR.match(text)
    if not m:
        return None
    base, sign, num = m.groups()
    try:
        value = int(num, 0)
    except ValueError:
        value = int(num, 16)
    return base, -value if sign == "-" else value


def parse_segment_expr(text: str) -> tuple[str, int] | None:
    """``.text:140001000`` -> ('.text', 0x140001000); the address part is hex like IDA's listing."""
    m = _SEGMENT_EXPR.match(text)
    return (m.group(1), int(m.group(2), 16)) if m else None


def parse_bare_hex(text: str) -> int | None:
    """``123e`` / ``401000h`` -> int; None when not pure hex."""
    m = _BARE_HEX.match(text)
    return int(m.group(1), 16) if m else None


def close_matches(query: str, pool: list[str], n: int = 5, cap: int = 20000) -> list[str]:
    """Up to ``n`` fuzzy suggestions: case-insensitive substring hits, then difflib ratio."""
    q = query.lower()
    if not q:
        return []
    found: list[str] = []
    window = max(3, len(q) // 3)
    nearby: dict[str, str] = {}
    for name in pool:
        low = name.lower()
        if q in low and len(found) < n and name not in found:
            found.append(name)
        elif abs(len(low) - len(q)) <= window and len(nearby) < cap:
            # ponytail: length window + cap bounds difflib cost on huge IDBs; add trigram index if misses matter
            nearby.setdefault(low, name)
    if len(found) < n:
        for low in difflib.get_close_matches(q, list(nearby), n=n - len(found), cutoff=0.6):
            if nearby[low] not in found:
                found.append(nearby[low])
    return found
