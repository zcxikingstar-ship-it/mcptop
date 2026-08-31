import json
import unittest

from mcptop.models import ConfiguredServer, Observation, ProcessInfo
from mcptop.render import redact_command, render_json


class RenderTests(unittest.TestCase):
    def test_redacts_common_secret_shapes(self):
        command = (
            "API_KEY=abc node server.js --token hunter2 "
            "https://user:pass@example.com/mcp?api_key=visible&safe=yes"
        )
        rendered = redact_command(command, max_chars=500)
        for secret in ("abc", "hunter2", "pass", "visible"):
            self.assertNotIn(secret, rendered)
        self.assertIn("safe=yes", rendered)

    def test_json_contract_is_parseable_and_redacted(self):
        server = ConfiguredServer(
            "claude",
            "demo",
            ("node", "demo-mcp.js"),
            "~/.claude.json",
            "user",
        )
        observation = Observation(
            process=ProcessInfo(
                10, 1, 1.0, 100, 50, "S", "node demo-mcp.js --api-key=secret"
            ),
            matches=[server],
            ancestry=[1],
            status="identified",
            reasons=["fixture"],
        )
        payload = json.loads(
            render_json(
                [observation],
                configured_count=1,
                problems=[],
                platform="darwin",
                detached_after=900,
            )
        )
        self.assertEqual(payload["schema_version"], 1)
        self.assertTrue(payload["read_only"])
        self.assertEqual(payload["processes"][0]["rss_bytes"], 102400)
        self.assertNotIn("secret", payload["processes"][0]["command_summary"])


if __name__ == "__main__":
    unittest.main()
