"""Shared vNext contracts and services for GUI and idalib runtimes.

This package deliberately has no IDA imports.  Runtime-specific adapters live
in :mod:`ida_pro_mcp.ida_mcp` and can therefore reuse these services without
making the supervisor import IDA modules.
"""

from .auth import AuthPolicy, WorkspacePolicy, create_token, default_token_path, load_token_file
from .contracts import (
    API_SCHEMA_VERSION,
    AnalysisEngine,
    AnalysisGraph,
    CapabilityManifest,
    Evidence,
    ErrorCode,
    Finding,
    InvestigationRecord,
    JobRecord,
    JobState,
    MutationOperation,
    MutationPreview,
    MutationReceipt,
    SafetyScope,
    ToolEnvelope,
    VNextError,
    normalize_public_addresses,
)
from .jobs import JobContext, JobManager
from .investigations import InvestigationManager
from .policy import CANONICAL_TOOLS, ToolPolicy, ToolPolicyRegistry
from .transactions import RevisionTracker, TransactionManager

__all__ = [
    "API_SCHEMA_VERSION",
    "AnalysisEngine",
    "AnalysisGraph",
    "AuthPolicy",
    "CANONICAL_TOOLS",
    "CapabilityManifest",
    "Evidence",
    "ErrorCode",
    "Finding",
    "InvestigationRecord",
    "InvestigationManager",
    "JobContext",
    "JobManager",
    "JobRecord",
    "JobState",
    "MutationOperation",
    "MutationPreview",
    "MutationReceipt",
    "RevisionTracker",
    "SafetyScope",
    "ToolEnvelope",
    "ToolPolicy",
    "ToolPolicyRegistry",
    "TransactionManager",
    "VNextError",
    "normalize_public_addresses",
    "WorkspacePolicy",
    "create_token",
    "default_token_path",
    "load_token_file",
]
