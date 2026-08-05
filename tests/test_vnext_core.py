from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from ida_pro_mcp.vnext.audit import AuditLog, redact
from ida_pro_mcp.vnext.auth import AuthPolicy, WorkspacePolicy, create_token
from ida_pro_mcp.vnext.contracts import (
    ErrorCode,
    JobState,
    MutationOperation,
    SafetyScope,
    ToolEnvelope,
    VNextError,
)
from ida_pro_mcp.vnext.investigations import InvestigationManager
from ida_pro_mcp.vnext.jobs import JobManager
from ida_pro_mcp.vnext.policy import CANONICAL_TOOLS, ToolPolicyRegistry, register_builtin_policies
from ida_pro_mcp.vnext.profiles import (
    DEFAULT_PROFILE_SCOPES,
    default_profile_enabled,
    quick_profile_selection,
)
from ida_pro_mcp.vnext.transactions import RevisionTracker, TransactionManager


def test_canonical_contract_is_bounded_and_complete():
    assert len(CANONICAL_TOOLS) == 35
    assert {"server_capabilities", "mutation_preview", "dataflow_trace", "python_execute"} <= CANONICAL_TOOLS


def test_canonical_envelope_serializes_addresses_as_hex_strings():
    result = ToolEnvelope({"addr": 0x401000, "nested": [{"target_ea": 0x402000}], "count": 3}).to_dict()
    assert result["data"] == {
        "addr": "0x401000",
        "nested": [{"target_ea": "0x402000"}],
        "count": 3,
    }


def test_policy_enforces_scopes_and_emits_annotations():
    registry = ToolPolicyRegistry()
    register_builtin_policies(registry)
    with pytest.raises(VNextError) as caught:
        registry.authorize("patch", {SafetyScope.READ})
    assert caught.value.code is ErrorCode.PROFILE_DENIED
    registry.authorize("patch", {SafetyScope.READ, SafetyScope.MODIFY})
    assert registry.get("patch").annotations()["destructiveHint"] is True
    assert registry.visible("list_funcs") is False
    assert registry.visible("list_funcs", legacy=True) is True


def test_quick_profiles_bound_tools_and_scopes():
    registry = ToolPolicyRegistry()
    register_builtin_policies(registry)
    tools = {
        "decompile": object(),
        "investigation_add_finding": object(),
        "patch": object(),
        "idb_save": object(),
        "debug_state": object(),
        "python_execute": object(),
        "mutation_commit": object(),
        "rename": object(),
    }

    read_tools, read_scopes = quick_profile_selection(" READ ", tools, registry)
    assert read_scopes == set()
    assert read_tools["decompile"] is True
    assert read_tools["investigation_add_finding"] is False
    assert read_tools["patch"] is False
    assert read_tools["idb_save"] is False
    assert read_tools["debug_state"] is False
    assert read_tools["python_execute"] is False
    assert read_tools["mutation_commit"] is False
    assert read_tools["rename"] is False  # legacy tools are never quick-profile enabled

    annotate_tools, annotate_scopes = quick_profile_selection(
        "annotate", tools, registry
    )
    assert annotate_scopes == {SafetyScope.ANNOTATE}
    assert annotate_tools["investigation_add_finding"] is True
    assert annotate_tools["patch"] is False

    modify_tools, modify_scopes = quick_profile_selection("modify", tools, registry)
    assert modify_scopes == set(DEFAULT_PROFILE_SCOPES - {SafetyScope.READ})
    assert modify_tools["mutation_commit"] is True
    assert modify_tools["idb_save"] is False
    assert modify_tools["debug_state"] is False
    assert modify_tools["python_execute"] is False
    assert default_profile_enabled("mutation_commit", registry) is True

    with pytest.raises(ValueError, match="Choose read, annotate, or modify"):
        quick_profile_selection("unknown", tools, registry)


def test_remote_auth_fails_closed_and_loopback_remains_frictionless():
    AuthPolicy("127.0.0.1").authorize_header(None)
    with pytest.raises(VNextError) as caught:
        AuthPolicy("0.0.0.0").validate_configuration()
    assert caught.value.code is ErrorCode.AUTH_REQUIRED

    token = create_token()
    policy = AuthPolicy("0.0.0.0", token)
    policy.validate_configuration()
    policy.authorize_header(f"Bearer {token}")
    with pytest.raises(VNextError):
        policy.authorize_header("Bearer incorrect")


def test_workspace_policy_rejects_escape(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    policy = WorkspacePolicy.from_values([allowed])
    assert policy.resolve(allowed / "binary.exe") == allowed / "binary.exe"
    with pytest.raises(VNextError):
        policy.resolve(tmp_path / "outside.exe")


def test_audit_redacts_secrets_and_large_payloads():
    value = redact({"authorization": "Bearer secret", "code": "print('secret')", "safe": "ok"})
    assert value == {"authorization": "<redacted>", "code": "<redacted>", "safe": "ok"}
    log = AuditLog(capacity=2)
    log.append(tool="python_execute", arguments={"code": "secret"}, outcome="success")
    assert log.records()[0]["arguments"]["code"] == "<redacted>"


def test_job_progress_result_and_cancellation():
    manager = JobManager(max_workers=1, max_jobs=4)
    release = threading.Event()

    def work(context):
        context.progress(0.25, "waiting")
        while not release.wait(0.01):
            context.check_cancelled()
        return [1, 2, 3]

    record = manager.submit("test", work)
    deadline = time.monotonic() + 2
    while manager.status(record.job_id)["state"] == JobState.QUEUED.value and time.monotonic() < deadline:
        time.sleep(0.01)
    assert manager.cancel(record.job_id)
    release.set()
    deadline = time.monotonic() + 2
    while manager.status(record.job_id)["state"] not in {JobState.CANCELLED.value, JobState.COMPLETED.value} and time.monotonic() < deadline:
        time.sleep(0.01)
    assert manager.status(record.job_id)["state"] == JobState.CANCELLED.value
    manager.shutdown()


def test_job_state_is_persisted_and_active_jobs_restore_as_interrupted():
    saved: dict = {}

    def save(state):
        saved.clear()
        saved.update(state)

    manager = JobManager(max_workers=1, save_state=save)
    release = threading.Event()
    record = manager.submit("resumable", lambda _context: release.wait(2), resumable=True)
    deadline = time.monotonic() + 2
    while saved.get(record.job_id, {}).get("state") == JobState.QUEUED.value and time.monotonic() < deadline:
        time.sleep(0.01)
    restored = JobManager(max_workers=1, load_state=lambda: saved)
    assert restored.status(record.job_id)["state"] == JobState.INTERRUPTED.value
    release.set()
    manager.shutdown()
    restored.shutdown()


def test_transaction_commit_detects_stale_revision_and_keeps_checkpoint():
    revisions = RevisionTracker()
    manager = TransactionManager(revisions, ttl_seconds=30)
    operation = MutationOperation("rename", {"items": []}, SafetyScope.ANNOTATE)
    preview = manager.preview(
        "db",
        [operation],
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        preview_operation=lambda op: {"kind": op.kind},
    )
    revisions.bump("db")
    with pytest.raises(VNextError) as caught:
        manager.commit(
            preview.transaction_id,
            database="db",
            enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
            checkpoint=lambda _tx: "checkpoint.i64",
            apply_operation=lambda _op: None,
        )
    assert caught.value.code is ErrorCode.STALE_REVISION

    fresh = manager.preview(
        "db",
        [operation],
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        preview_operation=lambda op: {"kind": op.kind},
    )
    receipt = manager.commit(
        fresh.transaction_id,
        database="db",
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        checkpoint=lambda _tx: "checkpoint.i64",
        apply_operation=lambda _op: None,
    )
    assert receipt.checkpoint == "checkpoint.i64"
    assert receipt.revision_after == receipt.revision_before + 1
    with pytest.raises(VNextError) as rollback:
        manager.rollback(fresh.transaction_id)
    assert rollback.value.code is ErrorCode.REOPEN_REQUIRED


def test_investigation_exports_are_deterministic():
    manager = InvestigationManager()
    record = manager.create("Find unsafe input flow", database="db", seeds=["main"])
    manager.add_finding(
        record.investigation_id,
        title="Unchecked copy",
        description="Input reaches a copy routine",
        severity="high",
        confidence=0.8,
        evidence=[{"address": "0x401000", "description": "call site", "source": "decompile"}],
    )
    first = manager.export(record.investigation_id, "json")
    second = manager.export(record.investigation_id, "json")
    assert first == second
    assert "Unchecked copy" in manager.export(record.investigation_id, "markdown")
    assert '"version": "2.1.0"' in manager.export(record.investigation_id, "sarif")
    assert manager.export(record.investigation_id, "dot").startswith("digraph")
