from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from ida_pro_mcp.vnext.audit import AuditLog, redact
from ida_pro_mcp.vnext.auth import AuthPolicy, WorkspacePolicy, create_token
from ida_pro_mcp.vnext.contracts import (
    API_SCHEMA_VERSION,
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
    assert annotate_tools["mutation_commit"] is True  # annotate-only sessions can commit
    assert annotate_tools["patch"] is False

    modify_tools, modify_scopes = quick_profile_selection("modify", tools, registry)
    assert modify_scopes == set(DEFAULT_PROFILE_SCOPES - {SafetyScope.READ})
    assert modify_tools["mutation_commit"] is True
    assert modify_tools["idb_save"] is False
    assert modify_tools["debug_state"] is False
    assert modify_tools["python_execute"] is False

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
    value = redact({"authorization": "Bearer secret", "password": "x", "safe": "ok"})
    assert value == {"authorization": "<redacted>", "password": "<redacted>", "safe": "ok"}
    assert redact({"code": "NOT_SUPPORTED"}, tool="job_result") == {"code": "NOT_SUPPORTED"}
    assert redact({"code": "print(1)"}, tool="python_execute") == {"code": "<redacted>"}
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
    record = manager.submit("resumable", lambda _context: release.wait(2))
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


def test_transaction_commit_without_checkpoint_uses_undo():
    revisions = RevisionTracker()
    manager = TransactionManager(revisions, ttl_seconds=30)
    operation = MutationOperation("rename", {"items": []}, SafetyScope.ANNOTATE)
    preview = manager.preview(
        "db",
        [operation],
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        preview_operation=lambda op: {"kind": op.kind},
    )
    receipt = manager.commit(
        preview.transaction_id,
        database="db",
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        checkpoint=lambda _tx: None,
        apply_operation=lambda _op: None,
        undo=lambda: True,
    )
    assert receipt.checkpoint is None
    assert receipt.undo_available is True
    rollback = manager.rollback(
        preview.transaction_id,
        rollback_undo=lambda: True,
    )
    assert rollback.status == "rolled_back"


def test_rollback_rejects_non_latest_and_repeated_transactions():
    revisions = RevisionTracker()
    manager = TransactionManager(revisions, ttl_seconds=30)
    operation = MutationOperation("rename", {"items": []}, SafetyScope.ANNOTATE)

    first = manager.preview(
        "db",
        [operation],
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        preview_operation=lambda op: {"kind": op.kind},
    )
    manager.commit(
        first.transaction_id,
        database="db",
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        checkpoint=lambda _tx: None,
        apply_operation=lambda _op: None,
        undo=lambda: True,
    )
    second = manager.preview(
        "db",
        [operation],
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        preview_operation=lambda op: {"kind": op.kind},
    )
    manager.commit(
        second.transaction_id,
        database="db",
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        checkpoint=lambda _tx: None,
        apply_operation=lambda _op: None,
        undo=lambda: True,
    )

    with pytest.raises(VNextError) as stale:
        manager.rollback(first.transaction_id, rollback_undo=lambda: True)
    assert stale.value.code is ErrorCode.STALE_REVISION

    receipt = manager.rollback(second.transaction_id, rollback_undo=lambda: True)
    assert receipt.status == "rolled_back"
    with pytest.raises(VNextError) as repeated:
        manager.rollback(second.transaction_id, rollback_undo=lambda: True)
    assert repeated.value.code is ErrorCode.INVALID_OPERATION


def test_partial_commit_failure_records_recovery_outcome():
    revisions = RevisionTracker()
    manager = TransactionManager(revisions, ttl_seconds=30)
    operations = [
        MutationOperation("rename", {"index": index}, SafetyScope.ANNOTATE)
        for index in range(2)
    ]
    preview = manager.preview(
        "db",
        operations,
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        preview_operation=lambda op: {"kind": op.kind},
    )
    applied = []
    recovered = []

    def apply(operation):
        if applied:
            raise RuntimeError("second operation failed")
        applied.append(operation)

    with pytest.raises(VNextError) as caught:
        manager.commit(
            preview.transaction_id,
            database="db",
            enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
            checkpoint=lambda _tx: "checkpoint.i64",
            apply_operation=apply,
            undo=lambda: recovered.append(True) or True,
        )

    transaction = caught.value.details["transaction"]
    assert transaction["status"] == "failed_rolled_back"
    assert transaction["applied_operations"] == 1
    assert transaction["checkpoint"] == "checkpoint.i64"
    assert transaction["error"]["message"] == "second operation failed"
    assert recovered == [True]
    assert manager.status(preview.transaction_id) == transaction


def test_investigation_job_link_does_not_overwrite_terminal_state():
    manager = InvestigationManager()
    record = manager.create("race", database="db")
    manager.set_state(record.investigation_id, "completed", result="ready")

    linked = manager.set_job(record.investigation_id, "job-1")

    assert linked.state == "completed"
    assert linked.job_id == "job-1"
    assert linked.metadata["result"] == "ready"


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


def test_commit_begin_called_once_and_undo_on_partial_failure():
    revisions = RevisionTracker()
    manager = TransactionManager(revisions, ttl_seconds=30)
    operations = [
        MutationOperation("rename", {"items": [{"addr": "0x1"}]}, SafetyScope.ANNOTATE),
        MutationOperation("rename", {"items": [{"addr": "0x2"}]}, SafetyScope.ANNOTATE),
    ]
    preview = manager.preview(
        "db",
        operations,
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        preview_operation=lambda op: {"kind": op.kind},
    )
    calls = {"begin": 0, "undo": 0, "applied": 0}

    def begin():
        calls["begin"] += 1
        return True

    def apply(operation):
        calls["applied"] += 1
        if calls["applied"] == 2:
            raise RuntimeError("second op failed")

    def undo():
        calls["undo"] += 1
        return True

    with pytest.raises(VNextError):
        manager.commit(
            preview.transaction_id,
            database="db",
            enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
            checkpoint=lambda _tx: "checkpoint.i64",
            apply_operation=apply,
            undo=undo,
            begin=begin,
        )
    assert calls["begin"] == 1
    assert calls["undo"] == 1
    receipt = manager._receipts[preview.transaction_id]
    assert receipt.status == "failed_rolled_back"


def test_rollback_without_checkpoint_names_disabled_checkpoints():
    revisions = RevisionTracker()
    manager = TransactionManager(revisions, ttl_seconds=30)
    preview = manager.preview(
        "db",
        [MutationOperation("rename", {"items": []}, SafetyScope.ANNOTATE)],
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        preview_operation=lambda op: {"kind": op.kind},
    )
    manager.commit(
        preview.transaction_id,
        database="db",
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        checkpoint=lambda _tx: None,
        apply_operation=lambda _op: None,
    )
    with pytest.raises(VNextError) as rollback:
        manager.rollback(preview.transaction_id, rollback_undo=lambda: False)
    assert rollback.value.code is ErrorCode.REOPEN_REQUIRED
    assert "recovery checkpoints are disabled" in str(rollback.value)


def test_tool_envelope_keeps_from_to_ints():
    envelope = ToolEnvelope({"from": 0, "to": 100}).to_dict()
    assert envelope["data"] == {"from": 0, "to": 100}


def test_investigation_restore_skips_corrupt_record():
    from ida_pro_mcp.vnext.investigations import InvestigationManager

    manager = InvestigationManager()
    good = {
        "objective": "ok",
        "database": "db",
        "state": "running",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "findings": [{"finding_id": "f1", "title": "t", "description": "d"}],
    }
    manager._restore({"good": good, "bad": {"findings": [{"nope": 1}]}})
    assert "good" in manager._records
    assert "bad" not in manager._records
    assert manager._records["good"].findings[0].finding_id == "f1"


def test_transaction_commit_accepts_unrelated_revision_bump_when_revalidated():
    revisions = RevisionTracker()
    manager = TransactionManager(revisions, ttl_seconds=30)
    operation = MutationOperation("rename", {"items": []}, SafetyScope.ANNOTATE)
    scopes = {SafetyScope.READ, SafetyScope.ANNOTATE}
    applied: list[str] = []

    rejected = manager.preview("db", [operation], enabled_scopes=scopes, preview_operation=lambda op: {"kind": op.kind})
    revisions.bump("db")
    with pytest.raises(VNextError) as caught:
        manager.commit(
            rejected.transaction_id,
            database="db",
            enabled_scopes=scopes,
            checkpoint=lambda _tx: None,
            apply_operation=lambda op: applied.append(op.kind),
            revalidate=lambda _preview: False,
        )
    assert caught.value.code is ErrorCode.STALE_REVISION
    assert applied == []

    accepted = manager.preview("db", [operation], enabled_scopes=scopes, preview_operation=lambda op: {"kind": op.kind})
    revisions.bump("db")
    receipt = manager.commit(
        accepted.transaction_id,
        database="db",
        enabled_scopes=scopes,
        checkpoint=lambda _tx: None,
        apply_operation=lambda op: applied.append(op.kind),
        revalidate=lambda preview: preview.transaction_id == accepted.transaction_id,
    )
    assert applied == ["rename"]
    assert receipt.status == "committed"
    assert any("re-verified" in warning for warning in receipt.warnings)


def _save_probing_lock(manager_ref: list, blocked: list):
    """save_state that, like an IDA main-thread hop, needs the manager from another thread."""

    def save(_state):
        probe = threading.Thread(target=lambda: manager_ref[0].list(), daemon=True)
        probe.start()
        probe.join(2)
        if probe.is_alive():
            blocked.append(True)

    return save


def test_job_persistence_never_holds_manager_lock():
    blocked: list = []
    ref: list = []
    manager = JobManager(max_workers=1, save_state=_save_probing_lock(ref, blocked))
    ref.append(manager)
    record = manager.submit("deep", lambda context: context.progress(0.5, "half") or "done")
    deadline = time.monotonic() + 10
    while manager.status(record.job_id)["state"] != JobState.COMPLETED.value and time.monotonic() < deadline:
        time.sleep(0.01)
    assert manager.result(record.job_id) == "done"
    assert blocked == []
    manager.shutdown()


def test_investigation_persistence_never_holds_manager_lock():
    blocked: list = []
    ref: list = []
    manager = InvestigationManager(save_state=_save_probing_lock(ref, blocked))
    ref.append(manager)
    record = manager.create("lock order", database="db")
    manager.set_job(record.investigation_id, "job-1")
    manager.add_finding(record.investigation_id, title="t", description="d")
    manager.set_state(record.investigation_id, "completed")
    assert blocked == []


def test_concurrent_update_during_save_is_not_blocked_and_latest_state_wins():
    saved: list = []
    entered = threading.Event()
    release = threading.Event()

    def save(state):
        saved.append(state)
        if len(saved) == 1:
            entered.set()
            release.wait(2)

    manager = InvestigationManager(save_state=save)
    creator = threading.Thread(target=lambda: manager.create("x", database="db"))
    creator.start()
    assert entered.wait(2)
    investigation_id = manager.list()[0]["investigation_id"]
    started = time.monotonic()
    manager.set_state(investigation_id, "completed")
    assert time.monotonic() - started < 1  # coalesced into the in-flight save
    release.set()
    creator.join(2)
    assert saved[-1][investigation_id]["state"] == "completed"


def test_rollback_requires_the_committed_transaction_scopes():
    registry = ToolPolicyRegistry()
    register_builtin_policies(registry)
    annotate = {SafetyScope.READ, SafetyScope.ANNOTATE}
    registry.authorize("mutation_commit", annotate)
    registry.authorize("mutation_rollback", annotate)

    manager = TransactionManager(RevisionTracker(), ttl_seconds=30)
    modify = annotate | {SafetyScope.MODIFY}
    preview = manager.preview(
        "db",
        [MutationOperation("patch_bytes", {"patches": []}, SafetyScope.MODIFY)],
        enabled_scopes=modify,
        preview_operation=lambda op: {},
    )
    with pytest.raises(VNextError) as denied_commit:
        manager.commit(preview.transaction_id, database="db", enabled_scopes=annotate, checkpoint=lambda _tx: None, apply_operation=lambda _op: None)
    assert denied_commit.value.code is ErrorCode.PROFILE_DENIED
    manager.commit(preview.transaction_id, database="db", enabled_scopes=modify, checkpoint=lambda _tx: None, apply_operation=lambda _op: None, undo=lambda: True)
    with pytest.raises(VNextError) as denied:
        manager.rollback(preview.transaction_id, rollback_undo=lambda: True, enabled_scopes=annotate)
    assert denied.value.code is ErrorCode.PROFILE_DENIED
    assert manager.rollback(preview.transaction_id, rollback_undo=lambda: True, enabled_scopes=modify).status == "rolled_back"


def test_finding_evidence_accepts_aliases_and_rejects_empty_items():
    manager = InvestigationManager()
    record = manager.create("evidence", database="db")
    finding = manager.add_finding(
        record.investigation_id,
        title="t",
        description="d",
        evidence=[
            {"addr": "main", "text": "call site"},
            {"ea": 0x401000, "data": {"k": 1}},
            {"address": "bogus", "note": "unresolved"},
            {"description": "context only"},
        ],
        resolve_address=lambda text: {"main": "0x401000"}[text],
    )
    assert [item.address for item in finding.evidence] == ["0x401000", "0x401000", "bogus", None]
    assert [item.description for item in finding.evidence] == ["call site", '{"k": 1}', "unresolved", "context only"]
    with pytest.raises(VNextError) as caught:
        manager.add_finding(record.investigation_id, title="t", description="d", evidence=[{"source": "x"}])
    assert caught.value.code is ErrorCode.INVALID_OPERATION
    assert len(manager.get(record.investigation_id).findings) == 1


def test_envelope_omits_default_fields():
    assert ToolEnvelope({"x": 1}).to_dict() == {"data": {"x": 1}, "schema_version": API_SCHEMA_VERSION}
    paged = ToolEnvelope([1], warnings=["w"], provenance={"engine": "e"}, truncated=True, next_cursor="c").to_dict()
    assert paged == {
        "data": [1],
        "warnings": ["w"],
        "provenance": {"engine": "e"},
        "truncated": True,
        "next_cursor": "c",
        "schema_version": API_SCHEMA_VERSION,
    }


def test_preview_wire_form_carries_change_fields_on_each_operation():
    manager = TransactionManager(RevisionTracker(), ttl_seconds=30)
    arguments = {"func": [{"addr": "0x1", "name": "a"}]}
    preview = manager.preview(
        "db",
        [MutationOperation("rename", arguments, SafetyScope.ANNOTATE)],
        enabled_scopes={SafetyScope.READ, SafetyScope.ANNOTATE},
        preview_operation=lambda op: {"validated": True, "before": {"func": [{"addr": "0x1", "name": "sub_1"}]}},
    )
    wire = preview.to_dict()
    assert "changes" not in wire and "warnings" not in wire
    assert wire["operations"] == [
        {
            "kind": "rename",
            "arguments": arguments,
            "scope": "annotate",
            "validated": True,
            "before": {"func": [{"addr": "0x1", "name": "sub_1"}]},
        }
    ]
