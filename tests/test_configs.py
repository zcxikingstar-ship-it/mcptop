import json
import tempfile
import unittest
from pathlib import Path

from mcptop.configs import discover_configured_servers


class ConfigDiscoveryTests(unittest.TestCase):
    def test_discovers_supported_clients_and_skips_remote_servers(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            project = base / "project"
            home.mkdir()
            project.mkdir()
            (project / ".git").mkdir()

            (home / ".codex").mkdir()
            (home / ".codex/config.toml").write_text(
                '[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp"]\n',
                encoding="utf-8",
            )
            (home / ".claude.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "browser": {"command": "uvx", "args": ["browser-mcp"]},
                            "remote": {
                                "type": "http",
                                "url": "https://example.com/mcp",
                            },
                        },
                        "projects": {
                            str(project): {
                                "mcpServers": {
                                    "local": {"command": "python -m local_mcp"}
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            (home / ".cursor").mkdir()
            (home / ".cursor/mcp.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "cursor-db": {"command": "node", "args": ["db-mcp.js"]}
                        }
                    }
                ),
                encoding="utf-8",
            )
            (home / ".config/opencode").mkdir(parents=True)
            (home / ".config/opencode/opencode.jsonc").write_text(
                """
                {
                  // V2 layout
                  "mcp": {"servers": {
                    "search": {
                      "type": "local",
                      "command": ["bunx", "search-mcp"],
                    },
                    "off": {
                      "type": "local",
                      "command": ["bunx", "off-mcp"],
                      "disabled": true,
                    },
                  }},
                }
                """,
                encoding="utf-8",
            )

            servers, problems = discover_configured_servers(home=home, cwd=project)
            identities = {(server.client, server.name) for server in servers}
            self.assertEqual(problems, [])
            self.assertEqual(
                identities,
                {
                    ("codex", "docs"),
                    ("claude", "browser"),
                    ("claude", "local"),
                    ("cursor", "cursor-db"),
                    ("opencode", "search"),
                },
            )
            commands = {server.name: server.command for server in servers}
            self.assertEqual(commands["local"], ("python", "-m", "local_mcp"))

    def test_reports_invalid_config_without_exposing_file_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            project = base / "project"
            home.mkdir()
            project.mkdir()
            (home / ".cursor").mkdir()
            (home / ".cursor/mcp.json").write_text(
                '{"secret": "do-not-print",', encoding="utf-8"
            )

            servers, problems = discover_configured_servers(home=home, cwd=project)
            self.assertEqual(servers, [])
            self.assertEqual(len(problems), 1)
            self.assertNotIn("do-not-print", problems[0].message)


if __name__ == "__main__":
    unittest.main()
