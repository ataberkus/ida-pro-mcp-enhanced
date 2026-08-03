"""Profile files whitelist MCP tools by name.

Format: one tool name per line; ``#`` starts a comment; blank lines are ignored.
Passed to ``idalib-mcp --profile PATH`` or exported from ``/config.html``.
"""

from pathlib import Path
from typing import Iterable

from ida_pro_mcp.vnext.contracts import SafetyScope


def parse_profile(text: str) -> set[str]:
    """Parse profile text into a set of tool names."""
    names: set[str] = set()
    for line in text.splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            names.add(name)
    return names


def load_profile(path: str | Path) -> set[str]:
    """Read a profile file and return its whitelisted tool names."""
    return parse_profile(Path(path).read_text(encoding="utf-8"))


def parse_profile_scopes(text: str) -> set[SafetyScope]:
    """Parse optional ``# scopes: annotate,modify`` profile metadata."""

    scopes = {SafetyScope.READ}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith("# scopes:"):
            continue
        for value in stripped.split(":", 1)[1].split(","):
            value = value.strip().lower()
            if value:
                scopes.add(SafetyScope(value))
    return scopes


def load_profile_scopes(path: str | Path) -> set[SafetyScope]:
    return parse_profile_scopes(Path(path).read_text(encoding="utf-8"))


def dump_profile(names: Iterable[str], *, header: str | None = None) -> str:
    """Serialize tool names into profile file format (deterministic order)."""
    lines = []
    if header:
        lines.extend(f"# {line}" for line in header.splitlines())
        lines.append("")
    lines.extend(sorted(names))
    return "\n".join(lines) + "\n"


def apply_profile(
    tools: dict,
    whitelist: set[str],
    *,
    protected: Iterable[str] = (),
) -> tuple[list[str], list[str]]:
    """Filter ``tools`` in place to ``whitelist`` plus ``protected`` names.

    Returns ``(kept, unknown)``: tools from the whitelist that survived, and
    whitelist entries that did not match any registered tool.
    """
    expanded = set(tools) if "*" in whitelist else set(whitelist)
    expanded.discard("*")
    keep = expanded | set(protected)
    unknown = sorted(expanded - set(tools))
    for name in list(tools):
        if name not in keep:
            tools.pop(name)
    kept = sorted(set(tools) & expanded)
    return kept, unknown
