"""Host-local discovery of running IDA MCP instances (bridge side, no IDA deps)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field


@dataclass
class InstanceInfo:
    id: str
    pid: int
    host: str
    port: int
    session_id: str
    idb_path: str
    input_file: str
    started_at: str


def sanitize_prefix(name: str) -> str:
    """Make an input file name a valid tool-name token."""
    s = name.lower()
    s = re.sub(r"[^a-z0-9_]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "ida"


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_registry_dir(registry_dir: str, probe: bool = True) -> list[InstanceInfo]:
    """Read registry JSON files, dropping entries whose PID is dead.

    probe=True additionally checks the port answers; kept injectable for tests.
    """
    out: list[InstanceInfo] = []
    if not os.path.isdir(registry_dir):
        return out
    for fname in os.listdir(registry_dir):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(registry_dir, fname), "r", encoding="utf-8") as f:
                d = json.load(f)
            inst = InstanceInfo(
                id=d["id"], pid=int(d["pid"]), host=d["host"], port=int(d["port"]),
                session_id=d.get("session_id", ""), idb_path=d.get("idb_path", ""),
                input_file=d.get("input_file", ""), started_at=d.get("started_at", ""),
            )
        except (OSError, ValueError, KeyError):
            continue
        if not _pid_alive(inst.pid):
            continue
        out.append(inst)
    return out


def assign_prefixes(instances: list[InstanceInfo]) -> dict[str, str]:
    """Map instance id -> tool prefix. Single instance => '' (unprefixed)."""
    if len(instances) == 1:
        return {instances[0].id: ""}
    prefixes: dict[str, str] = {}
    seen: dict[str, list[str]] = {}
    for inst in instances:
        base = sanitize_prefix(inst.input_file)
        seen.setdefault(base, []).append(inst.id)
    for base, ids in seen.items():
        if len(ids) == 1:
            prefixes[ids[0]] = f"{base}__"
        else:
            for iid in ids:
                prefixes[iid] = f"{base}_{iid[:4]}__"
    return prefixes


@dataclass
class InstanceTarget:
    id: str
    host: str
    port: int
    prefix: str


@dataclass
class ToolTable:
    targets: list[InstanceTarget]
    # exposed_name -> (target, inner_name)
    routes: dict[str, tuple[InstanceTarget, str]] = field(default_factory=dict)
    schemas: dict[str, dict] = field(default_factory=dict)

    def list_tools(self) -> list[dict]:
        return list(self.schemas.values())


def build_tool_table(targets: list[InstanceTarget], tools_by_id: dict[str, list[dict]]) -> ToolTable:
    table = ToolTable(targets=targets)
    for target in targets:
        for tool in tools_by_id.get(target.id, []):
            inner = tool["name"]
            exposed = f"{target.prefix}{inner}"
            if target.prefix == "" or exposed not in table.routes:
                table.routes[exposed] = (target, inner)
                schema = dict(tool)
                schema["name"] = exposed
                table.schemas[exposed] = schema
    # shared bridge-local tool
    table.schemas["ida_list_instances"] = {
        "name": "ida_list_instances",
        "description": "List running IDA instances and their tool prefixes.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    return table


def route_tool_call(table: ToolTable, exposed_name: str) -> tuple[str, int, str]:
    if exposed_name not in table.routes:
        raise KeyError(
            f"Unknown or unavailable tool '{exposed_name}'. "
            "Call ida_list_instances to see live instances and prefixes."
        )
    target, inner = table.routes[exposed_name]
    return target.host, target.port, inner
