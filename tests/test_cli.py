import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from mcptop.cli import main
from mcptop.models import ConfiguredServer, Observation, ProcessInfo


def sample_observation() -> Observation:
    server = ConfiguredServer(
        "codex", "docs", ("npx", "docs-mcp"), "~/.codex/config.toml", "user"
    )
    return Observation(
        process=ProcessInfo(20, 10, 0.1, 2048, 30, "S", "npx docs-mcp"),
        matches=[server],
        ancestry=[10, 1],
        client_ancestor="codex",
        client_ancestor_pid=10,
        reasons=["fixture"],
    )


class CliTests(unittest.TestCase):
    @patch("mcptop.cli._snapshot")
    def test_json_stdout_contains_only_json(self, snapshot):
        snapshot.return_value = ([sample_observation()], 1, [])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(["--json"])
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["processes"][0]["pid"], 20)

    @patch("mcptop.cli._snapshot")
    def test_explain_missing_pid_is_nonzero(self, snapshot):
        snapshot.return_value = ([sample_observation()], 1, [])
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            result = main(["--explain", "999"])
        self.assertEqual(result, 1)
        self.assertIn("not a running configured MCP process", stderr.getvalue())

    @patch("mcptop.cli.sys.platform", "win32")
    def test_windows_fails_fast_with_clear_message(self):
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            result = main([])
        self.assertEqual(result, 2)
        self.assertIn("macOS and Linux only", stderr.getvalue())

    @patch("mcptop.cli.time.sleep", side_effect=KeyboardInterrupt)
    @patch("mcptop.cli._snapshot")
    def test_watch_ctrl_c_exits_cleanly(self, snapshot, _sleep):
        snapshot.return_value = ([sample_observation()], 1, [])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = main(["--watch", "0.2"])
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
