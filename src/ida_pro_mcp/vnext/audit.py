"""Local structured audit log with deny-by-default argument redaction."""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any

_SECRET_KEYS = {
    "authorization",
    "token",
    "password",
    "secret",
    "api_key",
}

_CODE_TOOLS = {"python_execute", "py_eval", "py_exec_file"}
_CODE_KEYS = {"code", "source", "file_path", "path"}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def redact(value: Any, *, key: str = "", tool: str = "") -> Any:
    lowered = key.lower()
    if tool in _CODE_TOOLS and lowered in _CODE_KEYS:
        return "<redacted>"
    if lowered in _SECRET_KEYS or any(marker in lowered for marker in ("token", "password", "secret", "authorization")):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): redact(v, key=str(k), tool=tool) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item, tool=tool) for item in value]
    if isinstance(value, tuple):
        return [redact(item, tool=tool) for item in value]
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest(), "length": len(value)}
    if isinstance(value, str) and len(value) > 4096:
        return {"sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(), "length": len(value)}
    return value


@dataclass(frozen=True, slots=True)
class AuditRecord:
    timestamp: str
    session_id: str | None
    database: str | None
    tool: str
    safety_scopes: tuple[str, ...]
    arguments: Any
    outcome: str
    error_code: str | None = None


class AuditLog:
    def __init__(self, *, capacity: int = 1000) -> None:
        self._records: deque[AuditRecord] = deque(maxlen=max(1, capacity))
        self._lock = RLock()

    def append(
        self,
        *,
        tool: str,
        arguments: Any,
        outcome: str,
        session_id: str | None = None,
        database: str | None = None,
        safety_scopes: tuple[str, ...] = (),
        error_code: str | None = None,
    ) -> AuditRecord:
        record = AuditRecord(
            timestamp=_utc_now(),
            session_id=session_id,
            database=database,
            tool=tool,
            safety_scopes=safety_scopes,
            arguments=redact(arguments, tool=tool),
            outcome=outcome,
            error_code=error_code,
        )
        with self._lock:
            self._records.append(record)
        return record

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(record) for record in self._records]
