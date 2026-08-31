import unittest

from mcptop.analysis import analyze_processes, command_match_score, detect_client
from mcptop.models import ConfiguredServer, ProcessInfo


def process(
    pid: int,
    ppid: int,
    command: str,
    *,
    elapsed: int = 120,
    state: str = "S",
    rss: int = 1024,
) -> ProcessInfo:
    return ProcessInfo(pid, ppid, 0.5, rss, elapsed, state, command)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.server = ConfiguredServer(
            "codex",
            "filesystem",
            ("npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"),
            "~/.codex/config.toml",
            "user",
        )

    def test_matches_launcher_and_inherits_to_children(self):
        processes = [
            process(100, 1, "/usr/local/bin/codex"),
            process(200, 100, "npm exec @modelcontextprotocol/server-filesystem /tmp"),
            process(
                201,
                200,
                "node /cache/@modelcontextprotocol/server-filesystem/dist/index.js",
            ),
        ]
        observations = analyze_processes(processes, [self.server], detached_after=60)
        self.assertEqual({item.process.pid for item in observations}, {200, 201})
        self.assertTrue(all(item.status == "identified" for item in observations))
        child = next(item for item in observations if item.process.pid == 201)
        self.assertEqual(child.client_ancestor, "codex")

    def test_flags_old_detached_match_as_suspicious(self):
        processes = [
            process(1, 0, "/sbin/launchd", elapsed=100000),
            process(
                300,
                1,
                "node /cache/@modelcontextprotocol/server-filesystem/dist/index.js",
                elapsed=901,
            ),
        ]
        observations = analyze_processes(processes, [self.server], detached_after=900)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].status, "suspicious_detached")

    def test_zombie_is_suspicious_without_age_threshold(self):
        processes = [
            process(1, 0, "/sbin/init"),
            process(
                301,
                1,
                "node /cache/@modelcontextprotocol/server-filesystem/dist/index.js",
                elapsed=5,
                state="Z",
            ),
        ]
        observations = analyze_processes(processes, [self.server], detached_after=900)
        self.assertEqual(observations[0].status, "suspicious_detached")

    def test_generic_launcher_without_distinctive_token_does_not_match(self):
        generic = ConfiguredServer(
            "claude", "bad", ("python",), "~/.claude.json", "user"
        )
        self.assertEqual(
            command_match_score(process(10, 1, "python app.py"), generic), 0
        )

    def test_client_detection_is_executable_aware(self):
        self.assertEqual(detect_client(process(10, 1, "/usr/local/bin/codex")), "codex")
        self.assertIsNone(
            detect_client(process(11, 1, "node server.js --workspace codex-demo"))
        )

    def test_fixture_corpus_has_zero_active_false_positives(self):
        processes = [process(1, 0, "/sbin/init", elapsed=100000)]
        for index in range(50):
            client_pid = 1000 + index * 10
            server_pid = client_pid + 1
            processes.extend(
                [
                    process(client_pid, 1, "/usr/local/bin/codex", elapsed=2000),
                    process(
                        server_pid,
                        client_pid,
                        "npm exec @modelcontextprotocol/server-filesystem /tmp",
                        elapsed=1800,
                    ),
                ]
            )
        for index in range(10):
            processes.append(
                process(
                    5000 + index,
                    1,
                    "node /cache/@modelcontextprotocol/server-filesystem/dist/index.js",
                    elapsed=2000,
                )
            )

        observations = analyze_processes(processes, [self.server], detached_after=900)
        active = [item for item in observations if item.process.pid < 5000]
        detached = [item for item in observations if item.process.pid >= 5000]
        self.assertEqual(len(active), 50)
        self.assertTrue(all(item.status == "identified" for item in active))
        self.assertEqual(len(detached), 10)
        self.assertTrue(all(item.status == "suspicious_detached" for item in detached))


if __name__ == "__main__":
    unittest.main()
