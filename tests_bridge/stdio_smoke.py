"""Smoke test: launch the bridge over stdio and drive it like an MCP client.

Spawns `python bridge_server.py`, sends newline-delimited JSON-RPC, and verifies the
bridge starts (no ENOENT / import errors) and answers tools/list using live
discovery. Run while at least one IDA instance is up.

Usage:
    python tests_bridge/stdio_smoke.py
"""
import json
import os
import subprocess
import sys
import threading
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(REPO_ROOT, "src", "ida_pro_mcp", "bridge_server.py")


def main() -> int:
    proc = subprocess.Popen(
        [sys.executable, SERVER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=REPO_ROOT,
    )
    assert proc.stdin and proc.stdout and proc.stderr

    stderr_lines: list[str] = []

    def drain_stderr():
        for line in proc.stderr:
            stderr_lines.append(line.decode("utf-8", "replace").rstrip())

    threading.Thread(target=drain_stderr, daemon=True).start()

    def send(obj: dict):
        proc.stdin.write(json.dumps(obj).encode("utf-8") + b"\n")
        proc.stdin.flush()

    def read_response(timeout: float = 15.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
        raise TimeoutError("no response from bridge")

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "smoke", "version": "0"}}})
        init = read_response()
        server_info = init.get("result", {}).get("serverInfo", {})
        print(f"initialize -> serverInfo: {server_info}")

        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tl = read_response(timeout=20.0)
        tools = tl.get("result", {}).get("tools", [])
        names = [t["name"] for t in tools]
        print(f"tools/list -> {len(tools)} tools")
        print(f"  sample: {names[:6]}")
        has_list_instances = "ida_list_instances" in names
        print(f"  ida_list_instances present: {has_list_instances}")

        if has_list_instances:
            send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "ida_list_instances", "arguments": {}}})
            li = read_response(timeout=15.0)
            content = li.get("result", {}).get("content", [])
            text = content[0].get("text", "") if content else json.dumps(li.get("result"))
            print(f"  ida_list_instances -> {text}")

        ok = bool(server_info) and len(tools) > 0
        print(f"\nSMOKE {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if stderr_lines:
            print("\n--- bridge stderr ---")
            for l in stderr_lines[:20]:
                print(" ", l)


if __name__ == "__main__":
    sys.exit(main())
