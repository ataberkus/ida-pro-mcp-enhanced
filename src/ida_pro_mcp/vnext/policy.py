"""Canonical tool visibility and safety policy."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Iterable

from .contracts import ErrorCode, SafetyScope, VNextError

CANONICAL_TOOLS = frozenset(
    {
        "server_capabilities",
        "idb_open",
        "idb_list",
        "idb_save",
        "idb_close",
        "entity_query",
        "search",
        "memory_read",
        "disassemble",
        "decompile",
        "type_query",
        "int_convert",
        "signature_create",
        "analysis_run",
        "graph_query",
        "dataflow_trace",
        "taint_analyze",
        "job_status",
        "job_cancel",
        "job_result",
        "investigation_start",
        "investigation_get",
        "investigation_add_finding",
        "investigation_export",
        "mutation_preview",
        "mutation_commit",
        "mutation_status",
        "mutation_rollback",
        "debug_session",
        "debug_control",
        "debug_breakpoints",
        "debug_state",
        "debug_memory",
        "debug_trace",
        "python_execute",
    }
)


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    name: str
    scopes: frozenset[SafetyScope] = frozenset({SafetyScope.READ})
    read_only: bool = True
    destructive: bool = False
    idempotent: bool = True
    open_world: bool = False
    canonical: bool = False
    replacement: str | None = None

    def annotations(self) -> dict[str, bool]:
        return {
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.idempotent,
            "openWorldHint": self.open_world,
        }


class ToolPolicyRegistry:
    """Thread-safe metadata registry used independently of tool registration."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._policies: dict[str, ToolPolicy] = {}

    def register(self, policy: ToolPolicy) -> None:
        with self._lock:
            self._policies[policy.name] = policy

    def get(self, name: str) -> ToolPolicy:
        with self._lock:
            return self._policies.get(
                name,
                ToolPolicy(name=name, canonical=name in CANONICAL_TOOLS),
            )

    def set_scope(
        self,
        name: str,
        *scopes: SafetyScope,
        destructive: bool = True,
        idempotent: bool = False,
        open_world: bool = False,
        canonical: bool | None = None,
        replacement: str | None = None,
    ) -> None:
        effective = frozenset(scopes or (SafetyScope.READ,))
        self.register(
            ToolPolicy(
                name=name,
                scopes=effective,
                read_only=effective == frozenset({SafetyScope.READ}),
                destructive=destructive,
                idempotent=idempotent,
                open_world=open_world,
                canonical=name in CANONICAL_TOOLS if canonical is None else canonical,
                replacement=replacement,
            )
        )

    def authorize(self, name: str, enabled_scopes: Iterable[SafetyScope | str]) -> None:
        enabled = {SafetyScope(scope) for scope in enabled_scopes}
        required = self.get(name).scopes
        missing = required - enabled
        if missing:
            raise VNextError(
                ErrorCode.PROFILE_DENIED,
                f"Tool '{name}' requires disabled safety scopes",
                details={"required": sorted(s.value for s in required), "missing": sorted(s.value for s in missing)},
            )

    def visible(self, name: str, *, legacy: bool = False) -> bool:
        policy = self.get(name)
        return legacy or policy.canonical or name in CANONICAL_TOOLS

    def schemas(self) -> dict[str, ToolPolicy]:
        with self._lock:
            return dict(self._policies)


def register_builtin_policies(registry: ToolPolicyRegistry) -> None:
    for name in CANONICAL_TOOLS:
        registry.register(ToolPolicy(name=name, canonical=True))

    for name in {
        "add_bookmark",
        "set_comments",
        "append_comments",
        "rename",
        "declare_type",
        "set_type",
        "declare_stack",
        "delete_stack",
    }:
        registry.set_scope(name, SafetyScope.ANNOTATE, replacement="mutation_preview")
    registry.set_scope("enum_upsert", SafetyScope.ANNOTATE)
    for name in {
        "patch",
        "put_int",
        "patch_asm",
        "define_func",
        "define_code",
        "undefine",
        "set_op_type",
        "make_data",
    }:
        registry.set_scope(name, SafetyScope.MODIFY, replacement="mutation_preview")

    registry.register(ToolPolicy(name="mutation_preview", canonical=True))
    registry.register(
        ToolPolicy(
            name="mutation_commit",
            scopes=frozenset({SafetyScope.MODIFY}),
            read_only=False,
            destructive=True,
            idempotent=False,
            canonical=True,
        )
    )
    registry.register(
        ToolPolicy(
            name="mutation_rollback",
            scopes=frozenset({SafetyScope.MODIFY}),
            read_only=False,
            destructive=True,
            idempotent=False,
            canonical=True,
        )
    )

    registry.set_scope("idb_save", SafetyScope.FILESYSTEM)
    registry.register(ToolPolicy(name="investigation_start", scopes=frozenset({SafetyScope.READ}), read_only=False, destructive=False, idempotent=False, canonical=True))
    registry.register(ToolPolicy(name="job_cancel", scopes=frozenset({SafetyScope.READ}), read_only=False, destructive=False, idempotent=False, canonical=True))
    registry.register(ToolPolicy(name="investigation_export", scopes=frozenset({SafetyScope.READ}), read_only=True, destructive=False, idempotent=True, canonical=True))
    registry.set_scope("investigation_add_finding", SafetyScope.ANNOTATE)
    registry.set_scope("py_eval", SafetyScope.PYTHON, open_world=True, replacement="python_execute")
    registry.set_scope("py_exec_file", SafetyScope.PYTHON, SafetyScope.FILESYSTEM, open_world=True, replacement="python_execute")
    registry.set_scope("python_execute", SafetyScope.PYTHON, open_world=True)

    for name in {
        "dbg_start",
        "dbg_status",
        "dbg_exit",
        "dbg_detach",
        "dbg_continue",
        "dbg_run_to",
        "dbg_step_into",
        "dbg_step_over",
        "dbg_bps",
        "dbg_add_bp",
        "dbg_delete_bp",
        "dbg_toggle_bp",
        "dbg_regs",
        "dbg_stacktrace",
        "dbg_read",
        "dbg_write",
    }:
        registry.set_scope(name, SafetyScope.DEBUG, replacement="debug_session")
    for name in CANONICAL_TOOLS:
        if name.startswith("debug_"):
            registry.set_scope(name, SafetyScope.DEBUG)
