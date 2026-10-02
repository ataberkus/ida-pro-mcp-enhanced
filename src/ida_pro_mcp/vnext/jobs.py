"""Bounded asynchronous job manager with cooperative cancellation."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
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


class StateSaver:
    """Single-flight persistence that never calls ``save`` under the owner's lock.

    ``save`` may block on another thread (IDA main-thread dispatch) that itself
    needs the owner's lock, so callers MUST invoke :meth:`flush` after releasing
    it. Concurrent flushes coalesce; the last write always reflects the latest
    snapshot.
    """

    def __init__(
        self,
        lock: RLock,
        snapshot: Callable[[], dict[str, Any]],
        save: Callable[[dict[str, Any]], None] | None,
    ) -> None:
        self._lock = lock
        self._snapshot = snapshot
        self._save = save
        self._flushing = False
        self._pending = False

    def flush(self) -> None:
        if self._save is None:
            return
        with self._lock:
            if self._flushing:
                self._pending = True
                return
            self._flushing = True
        try:
            while True:
                with self._lock:
                    self._pending = False
                    state = self._snapshot()
                try:
                    self._save(state)
                except Exception:
                    # Persistence must not strand otherwise valid in-memory
                    # state (closing IDB, unavailable backend); memory wins.
                    pass
                with self._lock:
                    if not self._pending:
                        self._flushing = False
                        return
        except BaseException:
            with self._lock:
                self._flushing = False
            raise


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
        self._saver = StateSaver(
            self._lock,
            lambda: {key: value.to_dict() for key, value in self._records.items()},
            save_state,
        )
        self._on_change = on_change
        if load_state is not None:
            self._restore(load_state() or {})

    def submit(
        self,
        kind: str,
        callback: Callable[[JobContext], Any],
        *,
        database: str | None = None,
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
            )
            cancelled = Event()
            self._records[job_id] = record
            self._cancel[job_id] = cancelled
            future = self._executor.submit(self._run, job_id, callback, cancelled)
            self._futures[job_id] = future
            snapshot = self._copy(record)
        self._saver.flush()
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
            snapshot = self._copy(record)
        self._saver.flush()
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
                    f"Job is {record.state.value}, not completed; call job_status(job_id, wait_sec=30) first",
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
            snapshot = self._copy(record)
        self._saver.flush()
        self._notify(snapshot)
        return True

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
                    schema_version=str(raw.get("schema_version", "unknown")),
                )
            except (TypeError, ValueError):
                continue
            self._records[job_id] = record
            self._cancel[job_id] = Event()

    @staticmethod
    def _copy(record: JobRecord) -> JobRecord:
        return replace(record)
