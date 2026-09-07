"""Two-step mutation transactions with revision and checkpoint guards."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any, Callable, Iterable
from uuid import uuid4

from .contracts import (
    ErrorCode,
    MutationOperation,
    MutationPreview,
    MutationReceipt,
    SafetyScope,
    VNextError,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class RevisionTracker:
    def __init__(self) -> None:
        self._lock = RLock()
        self._revisions: dict[str, int] = {}

    def current(self, database: str) -> int:
        with self._lock:
            return self._revisions.get(database, 0)

    def bump(self, database: str) -> int:
        with self._lock:
            revision = self._revisions.get(database, 0) + 1
            self._revisions[database] = revision
            return revision

    def set(self, database: str, revision: int) -> None:
        with self._lock:
            self._revisions[database] = max(0, int(revision))


class TransactionManager:
    def __init__(self, revisions: RevisionTracker | None = None, *, ttl_seconds: int = 900) -> None:
        self.revisions = revisions or RevisionTracker()
        self.ttl_seconds = max(1, ttl_seconds)
        self._lock = RLock()
        self._previews: dict[str, MutationPreview] = {}
        self._receipts: dict[str, MutationReceipt] = {}

    def preview(
        self,
        database: str,
        operations: Iterable[MutationOperation | dict[str, Any]],
        *,
        enabled_scopes: Iterable[SafetyScope | str],
        preview_operation: Callable[[MutationOperation], dict[str, Any]],
        checkpoint_estimate_bytes: int | None = None,
    ) -> MutationPreview:
        parsed = [item if isinstance(item, MutationOperation) else MutationOperation.from_dict(item) for item in operations]
        if not parsed:
            raise VNextError(ErrorCode.INVALID_OPERATION, "At least one mutation operation is required")
        enabled = {SafetyScope(scope) for scope in enabled_scopes}
        required = {operation.scope for operation in parsed}
        missing = required - enabled
        changes = [preview_operation(operation) for operation in parsed]
        transaction_id = str(uuid4())
        expires = _utc_now() + timedelta(seconds=self.ttl_seconds)
        preview = MutationPreview(
            transaction_id=transaction_id,
            database=database,
            revision=self.revisions.current(database),
            operations=parsed,
            required_scopes=sorted(scope.value for scope in required),
            changes=changes,
            warnings=(
                ["Commit requires additional safety scopes: " + ", ".join(sorted(scope.value for scope in missing))]
                if missing
                else []
            ),
            expires_at=expires.isoformat(),
            checkpoint_estimate_bytes=checkpoint_estimate_bytes,
        )
        with self._lock:
            self._previews[transaction_id] = preview
        return preview

    def commit(
        self,
        transaction_id: str,
        *,
        database: str,
        enabled_scopes: Iterable[SafetyScope | str],
        checkpoint: Callable[[str], str | None],
        apply_operation: Callable[[MutationOperation], Any],
        undo: Callable[[], bool] | None = None,
    ) -> MutationReceipt:
        with self._lock:
            preview = self._get_live_preview(transaction_id)
            if preview.database != database:
                raise VNextError(ErrorCode.INVALID_DATABASE, "Transaction belongs to another database")
            current_revision = self.revisions.current(database)
            if current_revision != preview.revision:
                raise VNextError(
                    ErrorCode.STALE_REVISION,
                    "Database changed after mutation preview",
                    details={"expected": preview.revision, "actual": current_revision},
                )
            enabled = {SafetyScope(scope) for scope in enabled_scopes}
            required = {SafetyScope(scope) for scope in preview.required_scopes}
            if missing := required - enabled:
                raise VNextError(
                    ErrorCode.PROFILE_DENIED,
                    "Mutation commit lost required safety scopes",
                    details={"missing": sorted(scope.value for scope in missing)},
                )

            checkpoint_path = checkpoint(transaction_id)
            applied_operations = 0
            try:
                for operation in preview.operations:
                    apply_operation(operation)
                    applied_operations += 1
            except Exception as exc:
                restored = False
                recovery_error: str | None = None
                if applied_operations and undo is not None:
                    try:
                        restored = bool(undo())
                    except Exception as undo_exc:
                        recovery_error = str(undo_exc)
                revision_after = (
                    self.revisions.bump(database)
                    if applied_operations
                    else self.revisions.current(database)
                )
                if isinstance(exc, VNextError):
                    error = exc.to_dict()
                    code = exc.code
                    message = str(exc)
                    details = dict(exc.details)
                else:
                    error = {"code": ErrorCode.INVALID_OPERATION.value, "message": str(exc)}
                    code = ErrorCode.INVALID_OPERATION
                    message = str(exc)
                    details = {}
                receipt = MutationReceipt(
                    transaction_id=transaction_id,
                    database=database,
                    revision_before=preview.revision,
                    revision_after=revision_after,
                    committed_at=_utc_now().isoformat(),
                    checkpoint=checkpoint_path,
                    undo_available=False,
                    status="failed_rolled_back" if restored else "failed",
                    warnings=(
                        ["Applied operations were rolled back after commit failure"]
                        if restored
                        else (
                            ["Commit failed after applying one or more operations"]
                            if applied_operations
                            else ["Commit failed before applying any operation"]
                        )
                    )
                    + ([f"Automatic recovery failed: {recovery_error}"] if recovery_error else []),
                    applied_operations=applied_operations,
                    error=error,
                )
                self._receipts[transaction_id] = receipt
                self._previews.pop(transaction_id, None)
                details["transaction"] = receipt.to_dict()
                raise VNextError(code, message, details=details) from exc

            revision_after = self.revisions.bump(database)
            receipt = MutationReceipt(
                transaction_id=transaction_id,
                database=database,
                revision_before=preview.revision,
                revision_after=revision_after,
                committed_at=_utc_now().isoformat(),
                checkpoint=checkpoint_path,
                undo_available=undo is not None,
                applied_operations=applied_operations,
            )
            self._receipts[transaction_id] = receipt
            self._previews.pop(transaction_id, None)
            return receipt

    def status(self, transaction_id: str) -> dict[str, Any]:
        with self._lock:
            receipt = self._receipts.get(transaction_id)
            if receipt is not None:
                return receipt.to_dict()
            preview = self._previews.get(transaction_id)
            if preview is None:
                raise VNextError(ErrorCode.TRANSACTION_NOT_FOUND, f"Unknown transaction: {transaction_id}")
            result = preview.to_dict()
            result["status"] = "previewed"
            result["expired"] = datetime.fromisoformat(preview.expires_at) <= _utc_now()
            return result

    def rollback(
        self,
        transaction_id: str,
        *,
        rollback_undo: Callable[[], bool] | None = None,
        restore_checkpoint: Callable[[str], bool] | None = None,
    ) -> MutationReceipt:
        with self._lock:
            receipt = self._receipts.get(transaction_id)
            if receipt is None:
                raise VNextError(ErrorCode.TRANSACTION_NOT_FOUND, f"No committed transaction: {transaction_id}")
            if receipt.status != "committed":
                raise VNextError(
                    ErrorCode.INVALID_OPERATION,
                    f"Transaction cannot be rolled back from state: {receipt.status}",
                    details={"status": receipt.status},
                )
            current_revision = self.revisions.current(receipt.database)
            if current_revision != receipt.revision_after:
                raise VNextError(
                    ErrorCode.STALE_REVISION,
                    "A newer database mutation prevents transaction rollback",
                    details={
                        "expected": receipt.revision_after,
                        "actual": current_revision,
                    },
                )
            restored = rollback_undo() if rollback_undo is not None else False
            if not restored and receipt.checkpoint and restore_checkpoint is not None:
                restored = restore_checkpoint(receipt.checkpoint)
            if not restored:
                raise VNextError(
                    ErrorCode.REOPEN_REQUIRED,
                    "Live rollback is unavailable; reopen the recovery checkpoint",
                    details={"checkpoint": receipt.checkpoint},
                )
            receipt.status = "rolled_back"
            receipt.revision_after = self.revisions.bump(receipt.database)
            receipt.undo_available = False
            return receipt

    def _get_live_preview(self, transaction_id: str) -> MutationPreview:
        with self._lock:
            preview = self._previews.get(transaction_id)
        if preview is None:
            raise VNextError(ErrorCode.TRANSACTION_NOT_FOUND, f"Unknown transaction: {transaction_id}")
        if datetime.fromisoformat(preview.expires_at) <= _utc_now():
            with self._lock:
                self._previews.pop(transaction_id, None)
            raise VNextError(ErrorCode.TRANSACTION_EXPIRED, "Mutation preview expired")
        return preview
