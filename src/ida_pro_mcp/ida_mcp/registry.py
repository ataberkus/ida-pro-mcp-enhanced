"""Plugin-side instance registry file management (stdlib only)."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

INSTANCE_ENV = "IDA_MCP_INSTANCE_DIR"


def registry_dir() -> str:
    override = os.environ.get(INSTANCE_ENV)
    if override:
        return override
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "ida-mcp", "instances")
    return os.path.join(os.path.expanduser("~"), ".local", "share", "ida-mcp", "instances")


def write_instance(pid: int, host: str, port: int, idb_path: str, input_file: str) -> dict:
    os.makedirs(registry_dir(), exist_ok=True)
    payload = {
        "id": f"pid{pid}-{uuid.uuid4().hex[:6]}",
        "pid": pid,
        "host": host,
        "port": port,
        "session_id": uuid.uuid4().hex,
        "idb_path": idb_path,
        "input_file": input_file,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    path = os.path.join(registry_dir(), f"{payload['id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    return payload


def remove_instance(instance_id: str) -> None:
    path = os.path.join(registry_dir(), f"{instance_id}.json")
    try:
        os.remove(path)
    except OSError:
        pass
