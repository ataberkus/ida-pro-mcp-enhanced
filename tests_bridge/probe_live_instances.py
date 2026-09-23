"""Manual live probe: prove running IDA MCP instances are independent databases.

This is NOT a pytest test — it is a manual diagnostic you run while one or more
IDA instances are up with the MCP plugin auto-started. It discovers instances
from the registry (no hardcoded ports) and calls a database-identifying tool on
each, confirming each port serves its own IDB.

Usage:
    python tests_bridge/probe_live_instances.py
"""
import http.client
import json
import os
import sys

# Allow running from the repo root or from within tests_bridge/.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import _load_module, IDA_MCP_DIR  # noqa: E402

_discovery = _load_module("ida_mcp_discovery_probe", IDA_MCP_DIR / "discovery.py")


def post(port: int, payload: dict) -> dict:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        conn.request(
            "POST", "/mcp", json.dumps(payload),
            {"Content-Type": "application/json", "Mcp-Session-Id": f"probe-{port}"},
        )
        resp = conn.getresponse()
        raw = resp.read().decode()
        if resp.status >= 400:
            return {"_http_error": f"{resp.status} {resp.reason}: {raw}"}
        return json.loads(raw)
    finally:
        conn.close()


def call(port: int, name: str, args: dict) -> str:
    r = post(port, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": name, "arguments": args}})
    if "result" in r:
        content = r["result"].get("content", [])
        return content[0].get("text", "") if content else json.dumps(r["result"])
    return "ERROR: " + json.dumps(r.get("error"))


def main() -> None:
    registry_dir = _discovery.get_instances_dir()
    if not os.path.isdir(registry_dir):
        print(f"No registry dir at {registry_dir} — is any IDA instance running?")
        return

    instances = []
    for fname in sorted(os.listdir(registry_dir)):
        if fname.endswith(".json"):
            with open(os.path.join(registry_dir, fname), encoding="utf-8") as f:
                instances.append(json.load(f))

    if not instances:
        print("Registry is empty — no live instances.")
        return

    print(f"Discovered {len(instances)} instance(s) from {registry_dir}\n")
    for inst in instances:
        port = inst["port"]
        expect = inst.get("input_file", "?")
        print(f"===== PORT {port} (registry: {expect}, pid {inst['pid']}) =====")
        print("  server_health ->", call(port, "server_health", {})[:200])
        print()


if __name__ == "__main__":
    main()
