"""Diagnose the intermittent 'all tools disabled' state on live instances.

Reads the per-IDB `enabled_tools` netnode via each instance's py_eval tool.
Run while instances are up: python tests_bridge/diag_enabled_tools.py
"""
import http.client
import json

PORTS = {13337: "RigorZ", 13338: "Launcher"}

CODE = r'''import ida_netnode, json
n = ida_netnode.netnode("$ ida_mcp.enabled_tools")
blob = n.getblob(0, "C")
if blob is None:
    print("NO enabled_tools netnode -> defaults to ALL ENABLED")
else:
    d = json.loads(blob)
    enabled = sum(1 for v in d.values() if v)
    print(f"enabled_tools: {enabled}/{len(d)} enabled")
    disabled = [k for k, v in d.items() if not v]
    print("disabled:", disabled)
'''


def call(port: int, code: str) -> str:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "py_eval", "arguments": {"code": code}}}
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        conn.request("POST", "/mcp", json.dumps(body),
                     {"Content-Type": "application/json", "Mcp-Session-Id": "diag"})
        r = json.loads(conn.getresponse().read().decode())
        if "result" in r:
            cc = r["result"].get("content", [])
            return cc[0].get("text", "") if cc else json.dumps(r["result"])
        return "ERROR: " + json.dumps(r.get("error"))
    finally:
        conn.close()


for port, name in PORTS.items():
    print(f"=== {name} (port {port}) ===")
    out = call(port, CODE)
    try:
        parsed = json.loads(out)
        print("  stdout:", parsed.get("stdout", "").strip())
        if parsed.get("stderr"):
            print("  stderr:", parsed["stderr"].strip())
    except (json.JSONDecodeError, TypeError):
        print(" ", out)
    print()
