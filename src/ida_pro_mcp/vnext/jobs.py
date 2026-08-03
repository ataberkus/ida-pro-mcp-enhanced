"""Bounded asynchronous job manager with cooperative cancellation."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Event, RLock
from typing import Any, Callable
from uuid import uuid4

from .contracts import ErrorCode, JobRecord, JobState, VNextError


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class JobContext:
    job_id: str
    _cancelled: Event
    _progress: Callable[[float, str], None]

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def check_cancelled(self) -> None:
        if self.cancelled:
            raise CancelledError("Job cancelled")

    def progress(self, value: float, message: str = "") -> None:
        self._progress(max(0.0, min(1.0, float(value))), message)


class CancelledError(RuntimeError):
    pass


class JobManager:
    def __init__(
        self,
        *,
        max_workers: int = 2,
        max_jobs: int = 256,
        load_state: Callable[[], dict[str, Any] | None] | None = None,
        save_state: Callable[[dict[str, Any]], None] | None = None,
        on_change: Callable[[JobRecord], None] | None = None,
    ) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max(1, max_workers), thread_name_prefix="ida-mcp-job")
        self._max_jobs = max(1, max_jobs)
        self._lock = RLock()
        self._records: dict[str, JobRecord] = {}
        self._cancel: dict[str, Event] = {}
        self._futures: dict[str, Future[Any]] = {}
        self._save_state = save_state
        self._on_change = on_change
        if load_state is not None:
            self._restore(load_state() or {})

    def submit(
        self,
        kind: str,
        callback: Callable[[JobContext], Any],
        *,
        database: str | None = None,
        resumable: bool = False,
    ) -> JobRecord:
        with self._lock:
            self._prune_locked()
            if len(self._records) >= self._max_jobs:
                raise VNextError(ErrorCode.LIMIT_EXCEEDED, "Maximum retained job count reached")
            job_id = str(uuid4())
            now = _utc_now()
            record = JobRecord(
                job_id=job_id,
                kind=kind,
                state=JobState.QUEUED,
                created_at=now,
                updated_at=now,
                database=database,
                resumable=resumable,
            )
            cancelled = Event()
            self._records[job_id] = record
            self._cancel[job_id] = cancelled
            self._persist_locked()
            future = self._executor.submit(self._run, job_id, callback, cancelled)
            self._futures[job_id] = future
            snapshot = self._copy(record)
        self._notify(snapshot)
        return snapshot

    def _run(self, job_id: str, callback: Callable[[JobContext], Any], cancelled: Event) -> None:
        self._update(job_id, state=JobState.RUNNING, message="running")
        context = JobContext(job_id, cancelled, lambda value, message: self._update(job_id, progress=value, message=message))
        try:
            context.check_cancelled()
            result = callback(context)
            context.check_cancelled()
        except CancelledError:
            self._update(job_id, state=JobState.CANCELLED, message="cancelled")
        except VNextError as exc:
            self._update(job_id, state=JobState.FAILED, message=str(exc), error=exc.to_dict())
        except Exception as exc:  # pragma: no cover - defensive boundary
            self._update(
                job_id,
                state=JobState.FAILED,
                message=str(exc),
                error={"code": "INTERNAL_ERROR", "message": str(exc)},
            )
        else:
            self._update(job_id, state=JobState.COMPLETED, progress=1.0, message="completed", result=result)

    def _update(self, job_id: str, **changes: Any) -> None:
        with self._lock:
            record = self._records[job_id]
            for key, value in changes.items():
                setattr(record, key, value)
            record.updated_at = _utc_now()
            self._persist_locked()
            snapshot = self._copy(record)
        self._notify(snapshot)

    def status(self, job_id: str, *, include_result: bool = False) -> dict[str, Any]:
        with self._lock:
            record = self._records.get(job_id)
            if record is None:
                raise VNextError(ErrorCode.JOB_INTERRUPTED, f"Unknown job: {job_id}")
            return record.to_dict(include_result=include_result)

    def result(self, job_id: str) -> Any:
        with self._lock:
            record = self._records.get(job_id)
            if record is None:
                raise VNextError(ErrorCode.JOB_INTERRUPTED, f"Unknown job: {job_id}")
            if record.state is not JobState.COMPLETED:
                raise VNextError(
                    ErrorCode.JOB_INTERRUPTED,
                    f"Job is not complete: {record.state.value}",
                    details={"state": record.state.value},
                )
            return record.result

    def list(self, *, database: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            records = [
                self._copy(record).to_dict(include_result=False)
                for record in self._records.values()
                if database is None or record.database in {None, database}
            ]
        return sorted(records, key=lambda item: (item["created_at"], item["job_id"]))

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            event = self._cancel.get(job_id)
            record = self._records.get(job_id)
            if event is None or record is None or record.state in {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}:
                return False
            event.set()
            future = self._futures.get(job_id)
            if future is not None and future.cancel():
                record.state = JobState.CANCELLED
                record.updated_at = _utc_now()
            self._persist_locked()
            snapshot = self._copy(record)
        self._notify(snapshot)
        return True

    def mark_running_interrupted(self) -> int:
        count = 0
        with self._lock:
            for record in self._records.values():
                if record.state in {JobState.QUEUED, JobState.RUNNING}:
                    record.state = JobState.INTERRUPTED
                    record.message = "worker restarted"
                    record.updated_at = _utc_now()
                    count += 1
            if count:
                self._persist_locked()
        return count

    def shutdown(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=True)

    def _prune_locked(self) -> None:
        terminal = [
            job_id
            for job_id, record in self._records.items()
            if record.state in {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED, JobState.INTERRUPTED}
        ]
        while len(self._records) >= self._max_jobs and terminal:
            job_id = terminal.pop(0)
            self._records.pop(job_id, None)
            self._cancel.pop(job_id, None)
            self._futures.pop(job_id, None)

    def _persist_locked(self) -> None:
        if self._save_state is not None:
            try:
                self._save_state({key: value.to_dict() for key, value in self._records.items()})
            except Exception:
                # Persistence must not strand an otherwise completed job in a
                # running state. The in-memory record remains authoritative.
                pass

    def _notify(self, record: JobRecord) -> None:
        if self._on_change is not None:
            self._on_change(record)

    def _restore(self, state: dict[str, Any]) -> None:
        for job_id, raw in state.items():
            try:
                restored_state = JobState(raw.get("state", JobState.INTERRUPTED.value))
                if restored_state in {JobState.QUEUED, JobState.RUNNING}:
                    restored_state = JobState.INTERRUPTED
                record = JobRecord(
                    job_id=job_id,
                    kind=str(raw.get("kind", "unknown")),
                    state=restored_state,
                    created_at=str(raw.get("created_at", _utc_now())),
                    updated_at=_utc_now(),
                    progress=float(raw.get("progress", 0.0)),
                    message=("worker restarted" if restored_state is JobState.INTERRUPTED else str(raw.get("message", ""))),
                    result=raw.get("result"),
                    error=raw.get("error"),
                    database=raw.get("database"),
                    resumable=bool(raw.get("resumable", False)),
                    schema_version=str(raw.get("schema_version", "unknown")),
                )
            except (TypeError, ValueError):
                continue
            self._records[job_id] = record
            self._cancel[job_id] = Event()

    @staticmethod
    def _copy(record: JobRecord) -> JobRecord:
        return JobRecord(**{**record.__dict__}) if hasattr(record, "__dict__") else JobRecord(
            job_id=record.job_id,
            kind=record.kind,
            state=record.state,
            created_at=record.created_at,
            updated_at=record.updated_at,
            progress=record.progress,
            message=record.message,
            result=record.result,
            error=record.error,
            database=record.database,
            resumable=record.resumable,
            schema_version=record.schema_version,
        )
