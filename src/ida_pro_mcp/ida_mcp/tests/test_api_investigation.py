"""Tests for high-level investigation workflow helpers and tool output."""

from ..framework import (
    assert_has_keys,
    assert_is_list,
    assert_shape,
    get_any_function,
    list_of,
    optional,
    skip_test,
    test,
)
from .. import __all__ as PACKAGE_EXPORTS
from ..api_investigation import (
    _build_artifact_clusters,
    _classify_string,
    _confidence_for_score,
    _make_artifact_lead,
    _make_function_lead,
    _normalize_goal,
    _score_function_candidate,
    investigate_binary,
)


def _sample_function(**overrides):
    item = {
        "addr": "0x1234",
        "name": "sub_1234",
        "size": 256,
        "xref_count": 4,
        "callee_count": 2,
        "type": "complex",
    }
    item.update(overrides)
    return item


@test()
def test_investigation_normalize_goal_defaults_and_warns():
    """Unknown investigation goals fall back to general with a warning."""
    assert _normalize_goal("malware") == ("malware", [])
    assert _normalize_goal("  VULN  ") == ("vuln", [])

    normalized, warnings = _normalize_goal("firmware")
    assert normalized == "general"
    assert warnings == ["Unsupported goal 'firmware'; using 'general'."]


@test()
def test_investigation_confidence_thresholds():
    """Lead confidence is deterministic at scoring boundaries."""
    assert _confidence_for_score(30) == "high"
    assert _confidence_for_score(18) == "medium"
    assert _confidence_for_score(8) == "low"


@test()
def test_investigation_function_scoring_goal_weights():
    """Goal profiles alter scoring without changing candidate shape."""
    network_candidate = _sample_function(import_categories=["network", "process"])
    crackme_candidate = _sample_function(type="leaf", constants=[0x1337, 0x401000])

    malware_score, malware_reasons = _score_function_candidate(network_candidate, "malware")
    general_score, _ = _score_function_candidate(network_candidate, "general")
    crackme_score, crackme_reasons = _score_function_candidate(crackme_candidate, "crackme")

    assert malware_score > general_score
    assert any("network" in reason for reason in malware_reasons)
    assert crackme_score >= 10
    assert any("constants" in reason for reason in crackme_reasons)


@test()
def test_investigation_classifies_strings():
    """String classification catches common reverse-engineering signals."""
    assert _classify_string("http://example.test/a") == "url"
    assert _classify_string("C:\\Temp\\sample.bin") == "path"
    assert _classify_string("IsDebuggerPresent") == "anti_debug"
    assert _classify_string("value=%08x") == "format"
    assert _classify_string("ordinary text") == "text"


@test()
def test_investigation_builds_artifact_clusters():
    """Import and string artifacts are clustered with scores and examples."""
    imports_by_category = {
        "network": [
            {"addr": "0x401000", "name": "connect", "module": "ws2_32"},
            {"addr": "0x401008", "name": "send", "module": "ws2_32"},
        ],
        "crypto": [{"addr": "0x401020", "name": "CryptHashData", "module": "advapi32"}],
        "other": [],
    }
    strings = [
        {"addr": "0x2000", "string": "http://example.test", "xref_count": 2},
        {"addr": "0x2010", "string": "%s failed", "xref_count": 1},
    ]

    clusters = _build_artifact_clusters(imports_by_category, strings, "malware")
    by_key = {(item["kind"], item["category"]): item for item in clusters}

    assert by_key[("imports", "network")]["count"] == 2
    assert by_key[("imports", "network")]["score"] > by_key[("imports", "crypto")]["score"]
    assert by_key[("strings", "url")]["examples"][0]["value"] == "http://example.test"


@test()
def test_investigation_make_function_lead_shape():
    """Function leads expose rationale, evidence, confidence, and next calls."""
    candidate = _sample_function(import_categories=["network"])
    score, reasons = _score_function_candidate(candidate, "malware")
    lead = _make_function_lead(candidate, score, reasons, "malware", rank=1)

    assert lead["rank"] == 1
    assert lead["kind"] == "function"
    assert lead["addr"] == "0x1234"
    assert lead["score"] == score
    assert lead["confidence"] in {"low", "medium", "high"}
    assert lead["rationale"] == reasons
    assert lead["suggested_calls"][0]["tool"] == "analyze_function"


@test()
def test_investigation_make_artifact_lead_shape():
    """Artifact clusters can become ranked leads without function addresses."""
    cluster = {
        "kind": "imports",
        "category": "network",
        "count": 2,
        "score": 20,
        "examples": [{"addr": "0x401000", "name": "connect", "module": "ws2_32"}],
        "rationale": "2 network import(s) indicate relevant behavior.",
    }

    lead = _make_artifact_lead(cluster, "malware", rank=3)
    assert lead["rank"] == 3
    assert lead["kind"] == "artifact_cluster"
    assert lead["category"] == "network"
    assert lead["suggested_calls"][0]["tool"] == "imports_query"


@test()
def test_investigate_binary_returns_required_schema():
    """investigate_binary returns compact ranked leads and required metadata."""
    result = investigate_binary(goal="general", depth="fast", max_leads=5)

    assert_has_keys(
        result,
        "summary",
        "profile",
        "ranked_leads",
        "artifact_clusters",
        "next_actions",
        "limits",
        "warnings",
    )
    assert result["profile"]["goal"] == "general"
    assert result["profile"]["depth"] == "fast"
    assert len(result["ranked_leads"]) <= 5
    assert_is_list(result["next_actions"], min_length=1)

    if result["ranked_leads"]:
        assert_shape(
            result["ranked_leads"][0],
            {
                "rank": int,
                "kind": str,
                "score": int,
                "confidence": str,
                "rationale": list_of(str, min_length=1),
                "evidence": dict,
                "suggested_calls": list_of(dict, min_length=1),
                "addr": optional(str),
                "name": optional(str),
                "category": optional(str),
            },
        )


@test()
def test_investigate_binary_unknown_goal_warns_and_falls_back():
    """Unsupported goals fall back to general but keep returning results."""
    result = investigate_binary(goal="firmware", depth="deep", max_leads=3)
    assert result["profile"]["goal"] == "general"
    assert result["profile"]["requested_goal"] == "firmware"
    assert len(result["ranked_leads"]) <= 3
    assert any("Unsupported goal" in warning for warning in result["warnings"])
    assert any("Only depth='fast'" in warning for warning in result["warnings"])


@test()
def test_investigation_module_exported_by_package():
    """The package imports api_investigation during normal plugin startup."""
    assert "api_investigation" in PACKAGE_EXPORTS


@test()
def test_investigate_binary_is_read_only_for_known_function():
    """investigate_binary does not rename or comment a known function."""
    import idaapi
    import idc

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    ea = int(fn_addr, 16)
    before_name = idaapi.get_name(ea)
    before_line_comment = idaapi.get_cmt(ea, False) or ""
    before_func_comment = idc.get_func_cmt(ea, False) or ""

    result = investigate_binary(goal="crackme", max_leads=5)
    assert result["ranked_leads"]

    assert idaapi.get_name(ea) == before_name
    assert (idaapi.get_cmt(ea, False) or "") == before_line_comment
    assert (idc.get_func_cmt(ea, False) or "") == before_func_comment


@test()
def test_investigate_binary_crackme_profile_returns_rationale():
    """The crackme profile returns ranked leads with human-useful reasons."""
    result = investigate_binary(goal="crackme", max_leads=10)
    assert result["profile"]["goal"] == "crackme"
    assert result["ranked_leads"]
    assert any(lead["rationale"] for lead in result["ranked_leads"])
    assert any(call["tool"] == "analyze_function" for call in result["next_actions"])