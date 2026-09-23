"""JSONC config handling: comments/trailing commas survive install with backup."""

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from ida_pro_mcp import installer
from ida_pro_mcp.installer import install_mcp_servers
from ida_pro_mcp.installer_tui import interactive_choose, interactive_select


class InstallerJsoncTests(unittest.TestCase):
    def test_jsonc_settings_installs_with_backup(self):
        import tempfile
        import os

        original = (
            '{\n'
            '  // VS Code style line comment\n'
            '  "mcpServers": {\n'
            '    /* block comment */\n'
            '    "other-server": {"command": "other"},\n'
            '  },\n'
            '}\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            settings = os.path.join(tmp, "settings.json")
            with open(settings, "w", encoding="utf-8") as f:
                f.write(original)
            spec = {"FakeClient": (tmp, "settings.json")}
            with mock.patch.object(
                installer, "_get_scope_config_spec", return_value=(spec, {})
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    install_mcp_servers(only=["FakeClient"])
            with open(settings + ".bak", encoding="utf-8") as f:
                self.assertEqual(f.read(), original)
            with open(settings, encoding="utf-8") as f:
                rewritten = json.loads(f.read())
            self.assertIn("ida-pro-mcp", rewritten["mcpServers"])
            self.assertIn("other-server", rewritten["mcpServers"])

    def test_empty_choice_returns_none(self):
        self.assertIsNone(interactive_choose([], "t"))
        self.assertIsNone(interactive_select([], "t"))


if __name__ == "__main__":
    unittest.main()
