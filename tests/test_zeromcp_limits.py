"""Transport caps: serve() returns the bound port; SSE is capped at 64."""

import http.client
import sys
import unittest

sys.path.insert(0, "tests")
from _mcp_spec_support import McpServer

def _load_jsonrpc_registry():
    import importlib

    ida_mcp_dir = str(
        __import__("pathlib").Path(__file__).resolve().parents[1]
        / "src"
        / "ida_pro_mcp"
        / "ida_mcp"
    )
    sys.path.insert(0, ida_mcp_dir)
    try:
        module = importlib.import_module("zeromcp.jsonrpc")
    finally:
        sys.path.remove(ida_mcp_dir)
    return module.JsonRpcRegistry


JsonRpcRegistry = _load_jsonrpc_registry()

from ida_pro_mcp.vnext.policy import ToolPolicyRegistry, register_builtin_policies


class RedactedErrorsTests(unittest.TestCase):
    def test_unhandled_exception_is_redacted(self):
        registry = JsonRpcRegistry()

        def boom():
            raise ValueError("boom")

        registry.method(boom, "boom")
        response = registry.dispatch({"jsonrpc": "2.0", "id": 1, "method": "boom"})
        assert response is not None
        message = response["error"]["message"]
        self.assertEqual(message, "Internal Error: ValueError: boom")
        self.assertNotIn("Traceback", message)


class PolicyAnnotationTests(unittest.TestCase):
    def test_start_and_cancel_are_not_read_only(self):
        registry = ToolPolicyRegistry()
        register_builtin_policies(registry)
        for name in ("investigation_start", "job_cancel"):
            self.assertFalse(registry.get(name).annotations()["readOnlyHint"])


class ServePortTests(unittest.TestCase):
    def test_serve_returns_bound_port(self):
        server = McpServer("port-test")
        try:
            bound = server.serve("127.0.0.1", 0)
            self.assertIsNotNone(bound)
            self.assertNotEqual(bound, 0)
            self.assertEqual(bound, server._http_server.server_address[1])
        finally:
            server.stop()


class SseConnectionCapTests(unittest.TestCase):
    def test_65th_sse_get_rejected_with_503(self):
        server = McpServer("sse-cap-test")
        try:
            bound = server.serve("127.0.0.1", 0)
            for i in range(64):
                server._sse_connections[f"fake-{i}"] = object()
            conn = http.client.HTTPConnection("127.0.0.1", bound, timeout=5)
            try:
                conn.request("GET", "/sse")
                response = conn.getresponse()
                response.read()
                self.assertEqual(response.status, 503)
            finally:
                conn.close()
        finally:
            server._sse_connections.clear()
            server.stop()


if __name__ == "__main__":
    unittest.main()
