"""High-level read-only investigation workflows for reverse engineering."""

from __future__ import annotations

import re
from typing import Annotated, Any

from .rpc import tool
from .sync import idasync, tool_timeout
from .api_core import _get_strings_cache
from .api_survey import (
    _MAX_FUNC_ITER,
    _build_call_graph_summary,
    _build_entrypoints,
    _build_imports_by_category,
    _build_interesting_functions,
    _build_interesting_strings,
    _build_metadata,
    _build_segments,
    _build_statistics,
)


VALID_GOALS = {"general", "malware", "vuln", "crackme", "comprehension"}

GOAL_CATEGORY_WEIGHTS: dict[str, dict[str, int]] = {
    "general": {
        "crypto": 8,
        "network": 8,
        "process": 6,
        "registry": 5,
        "file_io": 5,
        "url": 5,
        "path": 4,
        "format": 3,
        "anti_debug": 4,
    },
    "malware": {
        "network": 14,
        "process": 12,
        "registry": 11,
        "crypto": 10,
        "file_io": 8,
        "url": 12,
        "path": 7,
        "anti_debug": 10,
    },
    "vuln": {
        "network": 10,
        "file_io": 10,
        "process": 7,
        "format": 10,
        "path": 8,
        "crypto": 4,
        "anti_debug": 2,
    },
    "crackme": {
        "crypto": 12,
        "anti_debug": 12,
        "format": 7,
        "process": 5,
        "network": 2,
        "file_io": 4,
        "path": 3,
    },
    "comprehension": {
        "process": 7,
        "network": 6,
        "file_io": 6,
        "crypto": 5,
        "registry": 4,
        "format": 4,
        "path": 4,
        "anti_debug": 3,
    },
}


def _normalize_goal(goal: str | None) -> tuple[str, list[str]]:
    normalized = (goal or "general").strip().lower() or "general"
    if normalized in VALID_GOALS:
        return normalized, []
    return "general", [f"Unsupported goal {normalized!r}; using 'general'."]


def _confidence_for_score(score: int) -> str:
    if score >= 24:
        return "high"
    if score >= 12:
        return "medium"
    return "low"


def _score_function_candidate(candidate: dict[str, Any], goal: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    xref_count = int(candidate.get("xref_count") or 0)
    if xref_count:
        contribution = min(xref_count, 10)
        score += contribution
        reasons.append(f"referenced by {xref_count} location(s)")

    size = int(candidate.get("size") or 0)
    if size >= 512:
        score += 6
        reasons.append("large function")
    elif size >= 128:
        score += 3
        reasons.append("moderate function size")

    callee_count = int(candidate.get("callee_count") or 0)
    if callee_count >= 10:
        score += 8
        reasons.append("dispatcher-like call fan-out")
    elif callee_count >= 3:
        score += 4
        reasons.append("multiple callees")

    function_type = str(candidate.get("type") or "")
    if function_type == "complex":
        score += 5
        reasons.append("classified as complex")
    elif function_type == "dispatcher":
        score += 8
        reasons.append("classified as dispatcher")
    elif function_type == "leaf" and goal in {"crackme", "vuln"}:
        score += 3
        reasons.append("leaf routine may contain concentrated logic")

    name = str(candidate.get("name") or "")
    if name.startswith("sub_"):
        score += 3
        reasons.append("unnamed function")

    weights = GOAL_CATEGORY_WEIGHTS.get(goal, GOAL_CATEGORY_WEIGHTS["general"])
    for category in candidate.get("import_categories") or []:
        weight = weights.get(str(category), 0)
        if weight:
            score += weight
            reasons.append(f"related to {category} imports")

    constants = candidate.get("constants") or []
    if constants and goal == "crackme":
        score += min(len(constants) * 4, 12)
        reasons.append("notable constants for crackme analysis")

    return score, reasons


STRING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("url", re.compile(r"https?://|ftp://|www\.", re.IGNORECASE)),
    ("anti_debug", re.compile(r"debugger|isdebuggerpresent|ptrace|beingdebugged", re.IGNORECASE)),
    ("path", re.compile(r"(^[a-z]:\\)|/etc/|/tmp/|\\\\|\.dll|\.exe|\.sys", re.IGNORECASE)),
    ("format", re.compile(r"%[0-9.# +\-]*[sdxXup]")),
]


def _classify_string(value: str) -> str:
    for category, pattern in STRING_PATTERNS:
        if pattern.search(value):
            return category
    return "text"


def _cluster_score(kind: str, category: str, count: int, goal: str, xrefs: int = 0) -> int:
    weights = GOAL_CATEGORY_WEIGHTS.get(goal, GOAL_CATEGORY_WEIGHTS["general"])
    base = min(count, 10) + min(xrefs, 10)
    return base + weights.get(category, 0) + (2 if kind == "imports" else 0)


def _build_artifact_clusters(
    imports_by_category: dict[str, list[dict[str, Any]]],
    interesting_strings: list[dict[str, Any]],
    goal: str,
) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []

    for category, imports in sorted(imports_by_category.items()):
        if not imports or category == "other":
            continue
        examples = [
            {
                "addr": item.get("addr"),
                "name": item.get("name"),
                "module": item.get("module"),
            }
            for item in imports[:5]
        ]
        score = _cluster_score("imports", category, len(imports), goal)
        clusters.append(
            {
                "kind": "imports",
                "category": category,
                "count": len(imports),
                "score": score,
                "examples": examples,
                "rationale": f"{len(imports)} {category} import(s) indicate relevant behavior.",
            }
        )

    strings_by_category: dict[str, list[dict[str, Any]]] = {}
    for item in interesting_strings:
        value = str(item.get("string") or item.get("value") or "")
        category = _classify_string(value)
        if category == "text":
            continue
        strings_by_category.setdefault(category, []).append(item)

    for category, items in sorted(strings_by_category.items()):
        xrefs = sum(int(item.get("xref_count") or 0) for item in items)
        examples = [
            {
                "addr": item.get("addr"),
                "value": item.get("string") or item.get("value"),
                "xref_count": item.get("xref_count", 0),
            }
            for item in items[:5]
        ]
        score = _cluster_score("strings", category, len(items), goal, xrefs)
        clusters.append(
            {
                "kind": "strings",
                "category": category,
                "count": len(items),
                "score": score,
                "examples": examples,
                "rationale": f"{len(items)} {category} string(s) provide triage anchors.",
            }
        )

    clusters.sort(key=lambda item: item["score"], reverse=True)
    return clusters


def _function_followups(addr: str, goal: str) -> list[dict[str, Any]]:
    calls = [
        {"tool": "analyze_function", "arguments": {"addr": addr}},
        {"tool": "xrefs_to", "arguments": {"addr": addr}},
    ]
    if goal in {"malware", "vuln", "comprehension"}:
        calls.append({"tool": "callgraph", "arguments": {"roots": [addr], "max_depth": 2}})
    if goal in {"malware", "crackme"}:
        calls.append({"tool": "trace_data_flow", "arguments": {"addr": addr, "direction": "backward", "max_depth": 3}})
    return calls


def _artifact_followups(cluster: dict[str, Any]) -> list[dict[str, Any]]:
    if cluster["kind"] == "imports":
        example = cluster["examples"][0] if cluster.get("examples") else {}
        query: dict[str, Any] = {"filter": str(example.get("name") or "*"), "count": 50}
        if example.get("module"):
            query["module"] = str(example["module"])
        return [
            {
                "tool": "imports_query",
                "arguments": {"queries": query},
            }
        ]
    value = str(cluster["examples"][0].get("value", "")) if cluster.get("examples") else ""
    return [
        {
            "tool": "find_regex",
            "arguments": {"pattern": re.escape(value[:80])},
        }
    ]


def _make_function_lead(
    candidate: dict[str, Any],
    score: int,
    rationale: list[str],
    goal: str,
    rank: int,
) -> dict[str, Any]:
    addr = str(candidate.get("addr") or "")
    return {
        "rank": rank,
        "kind": "function",
        "addr": addr,
        "name": candidate.get("name"),
        "score": score,
        "confidence": _confidence_for_score(score),
        "rationale": rationale,
        "evidence": {
            "size": candidate.get("size"),
            "xref_count": candidate.get("xref_count", 0),
            "callee_count": candidate.get("callee_count", 0),
            "type": candidate.get("type"),
        },
        "suggested_calls": _function_followups(addr, goal),
    }


def _make_artifact_lead(cluster: dict[str, Any], goal: str, rank: int) -> dict[str, Any]:
    return {
        "rank": rank,
        "kind": "artifact_cluster",
        "category": cluster["category"],
        "score": cluster["score"],
        "confidence": _confidence_for_score(int(cluster["score"])),
        "rationale": [cluster["rationale"]],
        "evidence": {
            "kind": cluster["kind"],
            "count": cluster["count"],
            "examples": cluster["examples"],
        },
        "suggested_calls": _artifact_followups(cluster),
    }


def _normalize_depth(depth: str | None) -> tuple[str, list[str]]:
    requested = (depth or "fast").strip().lower() or "fast"
    if requested == "fast":
        return "fast", []
    return "fast", [f"Only depth='fast' is implemented; using 'fast' instead of {requested!r}."]


def _normalize_max_leads(max_leads: int) -> tuple[int, list[str]]:
    warnings: list[str] = []
    try:
        value = int(max_leads)
    except Exception:
        value = 15
        warnings.append("Invalid max_leads; using 15.")
    if value < 1:
        warnings.append("max_leads must be at least 1; using 1.")
        value = 1
    if value > 50:
        warnings.append("max_leads is capped at 50 for fast triage.")
        value = 50
    return value, warnings


def _rank_leads(
    functions: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    goal: str,
    max_leads: int,
) -> list[dict[str, Any]]:
    scored: list[tuple[int, str, dict[str, Any], list[str]]] = []
    for candidate in functions:
        score, reasons = _score_function_candidate(candidate, goal)
        if score > 0 and reasons:
            scored.append((score, "function", candidate, reasons))
    for cluster in clusters:
        scored.append((int(cluster["score"]), "artifact", cluster, [cluster["rationale"]]))

    scored.sort(key=lambda item: item[0], reverse=True)
    leads: list[dict[str, Any]] = []
    for rank, (score, kind, item, reasons) in enumerate(scored[:max_leads], start=1):
        if kind == "function":
            leads.append(_make_function_lead(item, score, reasons, goal, rank))
        else:
            leads.append(_make_artifact_lead(item, goal, rank))
    return leads


def _next_actions(leads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for lead in leads[:5]:
        for call in lead.get("suggested_calls", [])[:2]:
            key = (call.get("tool", ""), repr(call.get("arguments", {})))
            if key in seen:
                continue
            seen.add(key)
            actions.append(
                {
                    "reason": f"Follow up lead {lead['rank']}: {lead['kind']}",
                    "tool": call["tool"],
                    "arguments": call.get("arguments", {}),
                }
            )
    if not actions:
        actions.append({"reason": "Start with compact binary survey", "tool": "survey_binary", "arguments": {}})
    return actions


@tool
@idasync
@tool_timeout(120.0)
def mcpinvestigate_binary(
    goal: Annotated[str, "Analysis goal: general|malware|vuln|crackme|comprehension"] = "general",
    depth: Annotated[str, "Analysis depth; only 'fast' is implemented in this version"] = "fast",
    max_leads: Annotated[int, "Maximum ranked leads to return, capped at 50"] = 15,
) -> dict:
    """Run read-only fast triage and return ranked reverse-engineering leads.
    The tool combines binary survey signals, import and string clusters, and
    lightweight function scoring into compact leads with rationale and suggested
    follow-up MCP calls. Use goal profiles to bias ranking for general triage,
    malware analysis, vulnerability research, crackmes, or comprehension. The
    tool never renames, comments, patches, applies types, or modifies the IDB."""
    import idautils

    requested_goal = goal
    selected_goal, warnings = _normalize_goal(goal)
    selected_depth, depth_warnings = _normalize_depth(depth)
    lead_count, lead_warnings = _normalize_max_leads(max_leads)
    warnings.extend(depth_warnings)
    warnings.extend(lead_warnings)

    all_func_eas = list(idautils.Functions())
    truncated = len(all_func_eas) > _MAX_FUNC_ITER
    func_eas = all_func_eas[:_MAX_FUNC_ITER] if truncated else all_func_eas
    strings = _get_strings_cache()
    segments = _build_segments()

    metadata = _build_metadata()
    interesting_strings = _build_interesting_strings()
    interesting_functions = _build_interesting_functions(func_eas, truncated)
    imports_by_category = _build_imports_by_category()
    artifact_clusters = _build_artifact_clusters(imports_by_category, interesting_strings, selected_goal)
    ranked_leads = _rank_leads(interesting_functions, artifact_clusters, selected_goal, lead_count)

    if truncated:
        warnings.append(
            f"Binary has {len(all_func_eas)} functions; function scoring was limited to the first {_MAX_FUNC_ITER}."
        )

    return {
        "summary": {
            "module": metadata.get("module"),
            "arch": metadata.get("arch"),
            "functions": len(all_func_eas),
            "strings": len(strings),
            "segments": len(segments),
            "lead_count": len(ranked_leads),
        },
        "profile": {
            "requested_goal": requested_goal,
            "goal": selected_goal,
            "depth": selected_depth,
            "available_goals": sorted(VALID_GOALS),
        },
        "ranked_leads": ranked_leads,
        "artifact_clusters": artifact_clusters[:10],
        "next_actions": _next_actions(ranked_leads),
        "limits": {
            "max_leads": lead_count,
            "max_functions_scored": _MAX_FUNC_ITER,
            "functions_scored": len(func_eas),
            "interesting_strings": len(interesting_strings),
            "artifact_clusters_returned": min(len(artifact_clusters), 10),
        },
        "warnings": warnings,
        "survey": {
            "metadata": metadata,
            "statistics": _build_statistics(all_func_eas, len(strings), len(segments)),
            "entrypoints": _build_entrypoints(),
            "call_graph_summary": _build_call_graph_summary(func_eas),
        },
    }