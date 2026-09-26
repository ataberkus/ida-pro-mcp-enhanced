"""Investigation records and deterministic report exporters."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from threading import RLock
from typing import Any, Callable
from uuid import uuid4

from .contracts import Evidence, Finding, InvestigationRecord, VNextError, ErrorCode


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class InvestigationManager:
    def __init__(
        self,
        *,
        load_state: Callable[[], dict[str, Any] | None] | None = None,
        save_state: Callable[[dict[str, Any]], None] | None = None,
        on_change: Callable[[InvestigationRecord], None] | None = None,
    ) -> None:
        self._lock = RLock()
        self._records: dict[str, InvestigationRecord] = {}
        self._save_state = save_state
        self._on_change = on_change
        if load_state is not None:
            self._restore(load_state() or {})

    def create(self, objective: str, *, database: str | None, seeds: list[str] | None = None) -> InvestigationRecord:
        now = _utc_now()
        record = InvestigationRecord(
            investigation_id=str(uuid4()),
            objective=objective.strip(),
            database=database,
            state="created",
            created_at=now,
            updated_at=now,
            seeds=list(seeds or []),
        )
        if not record.objective:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Investigation objective cannot be empty")
        with self._lock:
            self._records[record.investigation_id] = record
            self._persist_locked()
        self._notify(record)
        return record

    def get(self, investigation_id: str) -> InvestigationRecord:
        with self._lock:
            record = self._records.get(investigation_id)
            if record is None:
                raise VNextError(ErrorCode.INVALID_OPERATION, f"Unknown investigation: {investigation_id}")
            return record

    def set_job(self, investigation_id: str, job_id: str) -> InvestigationRecord:
        with self._lock:
            record = self.get(investigation_id)
            record.job_id = job_id
            if record.state not in {"completed", "failed", "cancelled", "interrupted"}:
                record.state = "running"
            record.updated_at = _utc_now()
            self._persist_locked()
        self._notify(record)
        return record

    def set_state(self, investigation_id: str, state: str, **metadata: Any) -> InvestigationRecord:
        with self._lock:
            record = self.get(investigation_id)
            record.state = state
            record.metadata.update(metadata)
            record.updated_at = _utc_now()
            self._persist_locked()
        self._notify(record)
        return record

    def add_finding(
        self,
        investigation_id: str,
        *,
        title: str,
        description: str,
        severity: str = "info",
        confidence: float = 0.5,
        evidence: list[dict[str, Any]] | None = None,
        tags: list[str] | None = None,
    ) -> Finding:
        parsed_evidence = [
            Evidence(
                address=item.get("address"),
                description=str(item.get("description", "")),
                source=str(item.get("source", "user")),
                confidence=max(0.0, min(1.0, float(item.get("confidence", 1.0)))),
                metadata=dict(item.get("metadata", {})),
            )
            for item in (evidence or [])
        ]
        finding = Finding(
            finding_id=str(uuid4()),
            title=title.strip(),
            description=description.strip(),
            severity=severity.lower(),
            confidence=max(0.0, min(1.0, float(confidence))),
            evidence=parsed_evidence,
            tags=sorted(set(tags or [])),
        )
        if not finding.title:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Finding title cannot be empty")
        with self._lock:
            record = self.get(investigation_id)
            record.findings.append(finding)
            record.updated_at = _utc_now()
            self._persist_locked()
        self._notify(record)
        return finding

    def list(self, *, database: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            records = [
                record.to_dict()
                for record in self._records.values()
                if database is None or record.database in {None, database}
            ]
        return sorted(records, key=lambda item: (item["created_at"], item["investigation_id"]))

    def export(self, investigation_id: str, format: str) -> str:
        record = self.get(investigation_id)
        normalized = format.lower()
        if normalized == "json":
            return json.dumps(record.to_dict(), indent=2, sort_keys=True)
        if normalized == "markdown":
            return _to_markdown(record)
        if normalized == "sarif":
            return json.dumps(_to_sarif(record), indent=2, sort_keys=True)
        raise VNextError(ErrorCode.NOT_SUPPORTED, f"Unsupported report format: {format}")

    def _persist_locked(self) -> None:
        if self._save_state is not None:
            try:
                self._save_state({key: value.to_dict() for key, value in self._records.items()})
            except Exception:
                # Keep investigations usable when an IDB is closing or its
                # persistence backend is temporarily unavailable.
                pass

    def _notify(self, record: InvestigationRecord) -> None:
        if self._on_change is not None:
            self._on_change(record)

    def _restore(self, state: dict[str, Any]) -> None:
        for investigation_id, value in state.items():
            try:
                findings = []
                for raw in value.get("findings", []):
                    try:
                        findings.append(
                            Finding(
                                finding_id=raw["finding_id"],
                                title=raw["title"],
                                description=raw["description"],
                                severity=raw.get("severity", "info"),
                                confidence=float(raw.get("confidence", 0.5)),
                                evidence=[
                                    Evidence(**item)
                                    for item in raw.get("evidence", [])
                                    if isinstance(item, dict)
                                ],
                                tags=list(raw.get("tags", [])),
                            )
                        )
                    except (KeyError, TypeError, ValueError):
                        continue
                self._records[investigation_id] = InvestigationRecord(
                    investigation_id=investigation_id,
                    objective=value["objective"],
                    database=value.get("database"),
                    state=value.get("state", "interrupted"),
                    created_at=value["created_at"],
                    updated_at=value["updated_at"],
                    job_id=value.get("job_id"),
                    seeds=list(value.get("seeds", [])),
                    findings=findings,
                    metadata=dict(value.get("metadata", {})),
                    schema_version=value.get("schema_version", "unknown"),
                )
            except (KeyError, TypeError, ValueError):
                continue


def _to_markdown(record: InvestigationRecord) -> str:
    lines = [f"# Investigation: {record.objective}", "", f"State: `{record.state}`", ""]
    if not record.findings:
        lines.append("No findings recorded.")
    for finding in sorted(record.findings, key=lambda item: item.finding_id):
        lines.extend(
            [
                f"## {finding.title}",
                "",
                f"Severity: `{finding.severity}` · Confidence: `{finding.confidence:.2f}`",
                "",
                finding.description,
                "",
            ]
        )
        for evidence in finding.evidence:
            location = f" at `{evidence.address}`" if evidence.address else ""
            lines.append(f"- {evidence.description}{location} ({evidence.source})")
        if finding.evidence:
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _to_sarif(record: InvestigationRecord) -> dict[str, Any]:
    results = []
    for finding in sorted(record.findings, key=lambda item: item.finding_id):
        locations = []
        for evidence in finding.evidence:
            if evidence.address:
                locations.append({"logicalLocations": [{"name": evidence.address}]})
        results.append(
            {
                "ruleId": finding.finding_id,
                "level": {"critical": "error", "high": "error", "medium": "warning"}.get(finding.severity, "note"),
                "message": {"text": f"{finding.title}: {finding.description}"},
                "locations": locations,
                "properties": {"confidence": finding.confidence, "tags": finding.tags},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "ida-pro-mcp"}}, "results": results}],
    }
