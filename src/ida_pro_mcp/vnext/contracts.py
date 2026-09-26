"""Versioned wire contracts shared by every ida-pro-mcp runtime."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Generic, TypeVar

API_SCHEMA_VERSION = "2026-08-01"
_ADDRESS_KEYS = {"addr", "address", "ea", "start_ea", "end_ea", "target_ea", "call_ea"}


def normalize_public_addresses(value: Any, *, key: str | None = None) -> Any:
    """Convert address-shaped integer fields to canonical hexadecimal strings."""

    if isinstance(value, dict):
        return {
            item_key: normalize_public_addresses(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [normalize_public_addresses(item, key=key) for item in value]
    if isinstance(value, tuple):
        return [normalize_public_addresses(item, key=key) for item in value]
    if isinstance(value, int) and key is not None and (key in _ADDRESS_KEYS or key.endswith("_addr")):
        return hex(value)
    return value


class SafetyScope(str, Enum):
    READ = "read"
    ANNOTATE = "annotate"
    MODIFY = "modify"
    FILESYSTEM = "filesystem"
    DEBUG = "debug"
    PYTHON = "python"


class AnalysisEngine(str, Enum):
    REFERENCE_FLOW = "reference_flow"
    HEXRAYS_MICROCODE = "hexrays_microcode"


class ErrorCode(str, Enum):
    PROFILE_DENIED = "PROFILE_DENIED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    STALE_REVISION = "STALE_REVISION"
    INVALID_DATABASE = "INVALID_DATABASE"
    JOB_INTERRUPTED = "JOB_INTERRUPTED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    REOPEN_REQUIRED = "REOPEN_REQUIRED"
    TRANSACTION_EXPIRED = "TRANSACTION_EXPIRED"
    TRANSACTION_NOT_FOUND = "TRANSACTION_NOT_FOUND"
    INVALID_OPERATION = "INVALID_OPERATION"


class VNextError(RuntimeError):
    """Error with a stable code suitable for MCP structured responses."""

    def __init__(
        self,
        code: ErrorCode | str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = ErrorCode(code) if not isinstance(code, ErrorCode) else code
        self.details = details or {}
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": str(self),
            "details": self.details,
            "schema_version": API_SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class CapabilityManifest:
    runtime: str
    ida_version: str | None
    python_version: str
    database: str | None
    safety_scopes: tuple[str, ...] = (SafetyScope.READ.value,)
    analysis_engines: tuple[str, ...] = (AnalysisEngine.REFERENCE_FLOW.value,)
    hexrays_available: bool = False
    debugger_available: bool = False
    resource_subscriptions: bool = False
    database_revision: int = 0
    schema_version: str = API_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


T = TypeVar("T")


@dataclass(slots=True)
class ToolEnvelope(Generic[T]):
    data: T
    warnings: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False
    next_cursor: str | None = None
    schema_version: str = API_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return normalize_public_addresses(asdict(self))


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True, slots=True)
class Evidence:
    address: str | None
    description: str
    source: str
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    description: str
    severity: str = "info"
    confidence: float = 0.5
    evidence: list[Evidence] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AnalysisGraph:
    engine: AnalysisEngine
    fidelity: str
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    unsupported_edges: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False
    schema_version: str = API_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["engine"] = self.engine.value
        return normalize_public_addresses(value)


@dataclass(slots=True)
class InvestigationRecord:
    investigation_id: str
    objective: str
    database: str | None
    state: str
    created_at: str
    updated_at: str
    job_id: str | None = None
    seeds: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = API_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["findings"] = [finding.to_dict() for finding in self.findings]
        return value


@dataclass(slots=True)
class JobRecord:
    job_id: str
    kind: str
    state: JobState
    created_at: str
    updated_at: str
    progress: float = 0.0
    message: str = ""
    result: Any = None
    error: dict[str, Any] | None = None
    database: str | None = None
    schema_version: str = API_SCHEMA_VERSION

    def to_dict(self, *, include_result: bool = True) -> dict[str, Any]:
        value = asdict(self)
        value["state"] = self.state.value
        if not include_result:
            value.pop("result", None)
        return value


@dataclass(frozen=True, slots=True)
class MutationOperation:
    kind: str
    arguments: dict[str, Any]
    scope: SafetyScope

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "MutationOperation":
        try:
            kind = str(value["kind"]).strip()
            arguments = dict(value.get("arguments", {}))
            scope = SafetyScope(value.get("scope", SafetyScope.MODIFY.value))
        except (KeyError, TypeError, ValueError) as exc:
            raise VNextError(
                ErrorCode.INVALID_OPERATION,
                "Mutation operation must contain a valid kind, arguments, and scope",
            ) from exc
        if not kind:
            raise VNextError(ErrorCode.INVALID_OPERATION, "Mutation kind cannot be empty")
        return cls(kind=kind, arguments=arguments, scope=scope)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "arguments": self.arguments,
            "scope": self.scope.value,
        }


@dataclass(slots=True)
class MutationPreview:
    transaction_id: str
    database: str
    revision: int
    operations: list[MutationOperation]
    required_scopes: list[str]
    changes: list[dict[str, Any]]
    warnings: list[str]
    expires_at: str
    schema_version: str = API_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["operations"] = [operation.to_dict() for operation in self.operations]
        return value


@dataclass(slots=True)
class MutationReceipt:
    transaction_id: str
    database: str
    revision_before: int
    revision_after: int
    committed_at: str
    checkpoint: str | None
    undo_available: bool
    status: str = "committed"
    warnings: list[str] = field(default_factory=list)
    applied_operations: int = 0
    error: dict[str, Any] | None = None
    schema_version: str = API_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
