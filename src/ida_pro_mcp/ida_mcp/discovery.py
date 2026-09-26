"""Instance discovery for IDA Pro MCP.

IDA plugin instances register themselves by writing JSON files to
{ida_user_dir}/mcp/instances/. The MCP server discovers running
instances by reading these files and validating PID liveness.
"""

import datetime
import glob
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypedDict


class LaunchInstanceResult(TypedDict, total=False):
    success: bool
    host: str
    port: int
    binary: str
    pid: int
    message: str
    error: str


class InstanceInfo(TypedDict, total=False):
    host: str
    port: int
    pid: int
    binary: str
    idb_path: str
    started_at: str
    backend: str
    input_file: str


INSTANCE_DIR_ENV = "IDA_MCP_INSTANCE_DIR"

# Session-management tools answered by the idalib supervisor/worker itself.
IDB_MANAGEMENT_TOOLS = {"idb_open", "idb_list", "idb_close"}


def _get_ida_user_dir() -> str:
    if sys.platform == "win32":
        appdata = os.getenv("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return os.path.join(appdata, "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def get_instances_dir() -> str:
    override = os.environ.get(INSTANCE_DIR_ENV)
    if override:
        return override
    return os.path.join(_get_ida_user_dir(), "mcp", "instances")


def _instance_file_path(port: int) -> str:
    return os.path.join(get_instances_dir(), f"instance_{port}.json")


def _instance_token_path(port: int) -> str:
    return os.path.join(get_instances_dir(), f"instance_{port}.token")


def register_instance(
    host: str, port: int, pid: int, binary: str, idb_path: str, backend: str = "gui", *, input_file: str = "", auth_token: str | None = None
) -> str:
    """Write an instance registration file. Returns the file path."""
    info: InstanceInfo = {
        "host": host,
        "port": port,
        "pid": pid,
        "binary": binary,
        "idb_path": idb_path,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "backend": backend,
        "input_file": input_file,
    }
    instances_dir = get_instances_dir()
    os.makedirs(instances_dir, exist_ok=True)
    if auth_token is not None:
        from ida_pro_mcp.vnext.auth import write_token_file

        write_token_file(__import__("pathlib").Path(_instance_token_path(port)), auth_token)
    file_path = _instance_file_path(port)
    # Atomic write
    fd, tmp_path = tempfile.mkstemp(dir=instances_dir, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)
        os.replace(tmp_path, file_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return file_path


def unregister_instance(port: int) -> bool:
    """Remove an instance registration file. Returns True if removed."""
    file_path = _instance_file_path(port)
    try:
        os.unlink(_instance_token_path(port))
    except OSError:
        pass
    try:
        os.unlink(file_path)
        return True
    except OSError:
        return False


def is_pid_alive(pid: int) -> bool:
    """Check if a process is still running."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True  # Process exists, we lack permission
        except ProcessLookupError:
            return False
        except OSError:
            return False


def probe_instance(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if an instance is reachable via TCP."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def read_registry_dir(registry_dir: str, probe: bool = True) -> list[InstanceInfo]:
    """Read instance_*.json files in `registry_dir`, dropping stale entries."""
    if not os.path.isdir(registry_dir):
        return []

    def _drop_stale(file_path: str) -> None:
        for path in (file_path, file_path.removesuffix(".json") + ".token"):
            try:
                os.unlink(path)
            except OSError:
                pass

    result: list[InstanceInfo] = []
    pattern = os.path.join(registry_dir, "instance_*.json")
    for file_path in glob.glob(pattern):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                info: InstanceInfo = json.load(f)
        except (json.JSONDecodeError, OSError):
            _drop_stale(file_path)
            continue

        if not all(k in info for k in ("host", "port", "pid")):
            _drop_stale(file_path)
            continue

        if not is_pid_alive(info["pid"]):
            _drop_stale(file_path)
            continue

        # Secondary check: verify the instance is actually listening.
        # Catches PID reuse (Windows can recycle PIDs quickly) and
        # cases where the process is alive but the server crashed.
        if probe and not probe_instance(info["host"], info["port"], timeout=1.0):
            _drop_stale(file_path)
            continue

        result.append(info)

    result.sort(key=lambda x: x.get("started_at", ""))
    return result


def discover_instances() -> list[InstanceInfo]:
    """Scan the registered-instances dir, cleaning up stale entries."""
    return read_registry_dir(get_instances_dir())


# ---------------------------------------------------------------------------
# Bridge routing: map discovered instances to prefixed tool names.
# ---------------------------------------------------------------------------


def sanitize_prefix(name: str) -> str:
    """Make an input file name a valid tool-name token."""
    s = re.sub(r"[^a-z0-9_]+", "_", name.lower())
    return re.sub(r"_+", "_", s).strip("_") or "ida"


def assign_prefixes(instances: list[InstanceInfo]) -> dict[int, str]:
    """Map instance port -> tool prefix. Single instance => '' (unprefixed)."""
    if len(instances) == 1:
        return {instances[0]["port"]: ""}
    seen: dict[str, list[int]] = {}
    for inst in instances:
        base = sanitize_prefix(str(inst.get("input_file") or inst.get("binary", "")))
        seen.setdefault(base, []).append(inst["port"])
    prefixes: dict[int, str] = {}
    for base, ports in seen.items():
        for port in ports:
            prefixes[port] = f"{base}__" if len(ports) == 1 else f"{base}_port{port}__"
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


def _find_existing_idb(file_path: str) -> str | None:
    """Return the path of an existing IDB next to `file_path`, if any."""
    base = os.path.splitext(file_path)[0]
    for ext in (".i64", ".idb"):
        idb_path = base + ext
        if os.path.isfile(idb_path):
            return idb_path
    return None


def _get_ida_executable() -> str:
    """Return the executable path of the current IDA process (or the
    interpreter when not running inside IDA)."""
    if sys.platform == "linux":
        try:
            return os.readlink("/proc/self/exe")
        except OSError:
            pass
    return sys.executable


def launch_gui_instance(
    file_path: str,
    *,
    autonomous: bool = False,
    new_database: bool = False,
    timeout: int = 30,
) -> LaunchInstanceResult:
    """Launch a new IDA GUI process for `file_path` and wait for it to register."""
    if not os.path.isfile(file_path):
        return {"success": False, "error": f"File not found: {file_path}"}

    ida_exe = _get_ida_executable()
    if not os.path.isfile(ida_exe):
        return {"success": False, "error": f"Cannot find IDA executable: {ida_exe}"}

    target = file_path
    if not new_database:
        existing_idb = _find_existing_idb(file_path)
        if existing_idb:
            target = existing_idb

    args = [ida_exe]
    if autonomous:
        args.append("-A")
    if new_database:
        args.append("-c")
    args.append(target)

    before = {(i["host"], i["port"]) for i in discover_instances()}

    try:
        subprocess.Popen(
            args,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            if sys.platform == "win32" else 0,
        )
    except Exception as e:
        return {"success": False, "error": f"Failed to launch IDA: {e}"}

    if timeout == 0:
        return {"success": True, "message": "IDA launched, not waiting for registration"}

    deadline = time.monotonic() + timeout
    new_instance = None
    while time.monotonic() < deadline:
        time.sleep(1)
        for inst in discover_instances():
            key = (inst["host"], inst["port"])
            if key not in before:
                new_instance = inst
                break
        if new_instance:
            break

    if not new_instance:
        return {
            "success": True,
            "message": f"IDA launched but did not register within {timeout}s.",
        }

    return {
        "success": True,
        "host": new_instance["host"],
        "port": new_instance["port"],
        "binary": new_instance.get("binary", ""),
        "pid": int(new_instance["pid"]) if new_instance.get("pid") is not None else 0,
    }
