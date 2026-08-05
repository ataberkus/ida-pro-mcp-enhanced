"""Runtime-neutral capability and revision interfaces."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field
from typing import Callable, Protocol, TypeVar

from .contracts import AnalysisEngine, CapabilityManifest, SafetyScope

T = TypeVar("T")


class RuntimeAdapter(Protocol):
    runtime_name: str

    def database_id(self) -> str | None: ...

    def execute(self, callback: Callable[[], T]) -> T: ...

    def checkpoint(self, transaction_id: str) -> str | None: ...

    def capabilities(self) -> CapabilityManifest: ...


@dataclass(slots=True)
class LocalRuntimeAdapter:
    """Minimal adapter useful for the supervisor and non-IDA unit tests."""

    runtime_name: str = "local"
    database: str | None = None
    scopes: set[SafetyScope] = field(default_factory=lambda: {SafetyScope.READ})
    hexrays_available: bool = False
    debugger_available: bool = False

    def database_id(self) -> str | None:
        return self.database

    def execute(self, callback: Callable[[], T]) -> T:
        return callback()

    def checkpoint(self, transaction_id: str) -> str | None:
        return None

    def capabilities(self) -> CapabilityManifest:
        engines = [AnalysisEngine.REFERENCE_FLOW.value]
        if self.hexrays_available:
            engines.append(AnalysisEngine.HEXRAYS_MICROCODE.value)
        return CapabilityManifest(
            runtime=self.runtime_name,
            ida_version=None,
            python_version=platform.python_version() or sys.version.split()[0],
            database=self.database,
            safety_scopes=tuple(sorted(scope.value for scope in self.scopes)),
            analysis_engines=tuple(engines),
            hexrays_available=self.hexrays_available,
            debugger_available=self.debugger_available,
        )
