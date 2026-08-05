import sys

from ida_pro_mcp import bridge_server


def test_auth_init_writes_requested_token_file(tmp_path, monkeypatch):
    token_path = tmp_path / "auth.token"
    monkeypatch.setattr(
        sys,
        "argv",
        ["ida-pro-mcp", "--auth-token-file", str(token_path), "auth", "init"],
    )

    bridge_server.main()

    token = token_path.read_text(encoding="utf-8").strip()
    assert len(token) >= 32


def test_bridge_timeout_exceeds_ida_tool_deadlines(monkeypatch):
    monkeypatch.delenv(bridge_server._BRIDGE_TIMEOUT_ENV, raising=False)
    assert bridge_server._get_bridge_timeout_seconds() == 240.0


def test_bridge_timeout_can_be_overridden(monkeypatch):
    monkeypatch.setenv(bridge_server._BRIDGE_TIMEOUT_ENV, "300")
    assert bridge_server._get_bridge_timeout_seconds() == 300.0


def test_bridge_timeout_rejects_invalid_values(monkeypatch):
    monkeypatch.setenv(bridge_server._BRIDGE_TIMEOUT_ENV, "invalid")
    assert bridge_server._get_bridge_timeout_seconds() == 240.0
    monkeypatch.setenv(bridge_server._BRIDGE_TIMEOUT_ENV, "0")
    assert bridge_server._get_bridge_timeout_seconds() == 240.0
