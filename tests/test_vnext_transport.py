from __future__ import annotations

import gzip
import json
import threading
import urllib.error
import urllib.request

from _mcp_spec_support import McpHttpTestServer, McpServer
from zeromcp.jsonrpc import cancel_request, register_pending_request, unregister_pending_request


def test_http_authentication_happens_before_dispatch():
    server = McpServer("auth-test")
    calls = []

    @server.tool
    def probe() -> dict:
        calls.append(True)
        return {"ok": True}

    def authorize(header):
        if header != "Bearer correct":
            raise PermissionError("denied")

    server.http_authenticator = authorize
    with McpHttpTestServer(server) as harness:
        status, headers, _body = harness.post_jsonrpc("tools/call", {"name": "probe"})
        assert status == 401
        assert headers["WWW-Authenticate"].startswith("Bearer")
        assert calls == []

        status, _headers, body = harness.post_jsonrpc(
            "tools/call",
            {"name": "probe"},
            extra_headers={"Authorization": "Bearer correct"},
        )
        assert status == 200
        assert body["result"]["structuredContent"] == {"ok": True}
        assert calls == [True]


def test_compressed_request_limit_is_enforced_after_decompression():
    server = McpServer("compression-test")
    server.post_body_limit = 256
    with McpHttpTestServer(server) as harness:
        payload = gzip.compress(b"x" * 4096)
        request = urllib.request.Request(
            harness.base_url + "/mcp",
            data=payload,
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=5)
            raise AssertionError("compressed expansion should have been rejected")
        except urllib.error.HTTPError as exc:
            assert exc.code == 413


def test_valid_gzip_jsonrpc_request_is_accepted():
    server = McpServer("compression-test")
    payload = gzip.compress(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode())
    with McpHttpTestServer(server) as harness:
        request = urllib.request.Request(
            harness.base_url + "/mcp",
            data=payload,
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read())
        assert body["result"] == {}


def test_cancellation_ids_are_scoped_by_transport_session():
    ready = threading.Barrier(3)
    release = threading.Event()
    events = {}

    def register(scope):
        events[scope] = register_pending_request(7, scope)
        ready.wait()
        release.wait(2)
        unregister_pending_request(7, scope)

    threads = [threading.Thread(target=register, args=(scope,)) for scope in ("http:first", "http:second")]
    for thread in threads:
        thread.start()
    ready.wait()
    assert cancel_request(7, "http:first")
    assert events["http:first"].is_set()
    assert not events["http:second"].is_set()
    assert not cancel_request(7, "http:missing")
    release.set()
    for thread in threads:
        thread.join(2)
