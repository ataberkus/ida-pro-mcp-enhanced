"""Local structured audit log with deny-by-default argument redaction."""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any

_SECRET_KEYS = {
    "authorization",
    "token",
    "password",
    "secret",
    "api_key",
    "code",
    "source",
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def redact(value: Any, *, key: str = "") -> Any:
    lowered = key.lower()
    if lowered in _SECRET_KEYS or any(marker in lowered for marker in ("token", "password", "secret", "authorization")):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
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
    def __init__(self, *, capacity: int = 1000, jsonl_path: Path | None = None) -> None:
        self._records: deque[AuditRecord] = deque(maxlen=max(1, capacity))
        self._jsonl_path = jsonl_path
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
            arguments=redact(arguments),
            outcome=outcome,
            error_code=error_code,
        )
        with self._lock:
            self._records.append(record)
            if self._jsonl_path is not None:
                self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
                with self._jsonl_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(asdict(record), sort_keys=True) + "\n")
        return record

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(record) for record in self._records]
