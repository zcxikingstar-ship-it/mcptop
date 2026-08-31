import unittest

from mcptop.processes import parse_elapsed, parse_ps_output


class ProcessParsingTests(unittest.TestCase):
    def test_parse_elapsed_variants(self):
        self.assertEqual(parse_elapsed("42"), 42)
        self.assertEqual(parse_elapsed("02:03"), 123)
        self.assertEqual(parse_elapsed("01:02:03"), 3723)
        self.assertEqual(parse_elapsed("2-01:02:03"), 176523)

    def test_parse_ps_output_keeps_command_tail(self):
        output = " 123  10  1.5  2048  01:02:03  S+  node /tmp/a b --flag\n"
        processes = parse_ps_output(output)
        self.assertEqual(len(processes), 1)
        process = processes[0]
        self.assertEqual(process.pid, 123)
        self.assertEqual(process.ppid, 10)
        self.assertEqual(process.rss_kb, 2048)
        self.assertEqual(process.elapsed_seconds, 3723)
        self.assertEqual(process.command, "node /tmp/a b --flag")

    def test_parse_ps_output_skips_malformed_rows(self):
        output = "header-like garbage\n1 0 0.0 10 00:01 S init\n"
        processes = parse_ps_output(output)
        self.assertEqual([process.pid for process in processes], [1])


if __name__ == "__main__":
    unittest.main()
