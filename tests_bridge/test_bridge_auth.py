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
