"""summary.py: счётчики и таблица находок для лога CI."""
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

from _helpers import TOOLS, make_finding, temp_dir

SECRET_EVIDENCE = "API_KEY = [REDACTED] and raw tool output that must not be printed"


def run_summary(cwd, *args):
    return subprocess.run([sys.executable, str(TOOLS / "summary.py"), *args],
                          capture_output=True, text=True, encoding="utf-8",
                          check=False, cwd=cwd)


def write_run(root, findings, name="2026-10-13-scout"):
    run = Path(root) / "reports" / name
    run.mkdir(parents=True)
    (run / "findings.json").write_text(json.dumps(findings), encoding="utf-8")


def sample():
    return [
        {**make_finding("high", "semgrep", "tools/a.py", 7, "rule: bad | thing"),
         "evidence": SECRET_EVIDENCE},
        {**make_finding("critical", "secrets", "app.py", 4, "possible secret: API_KEY"),
         "evidence": SECRET_EVIDENCE},
        make_finding("medium", "ruff", "tools/b.py", 1, "F401"),
        make_finding("low", "todo-fixme", "tools/c.py", 2, "later"),
    ]


class SummaryTest(unittest.TestCase):
    def test_default_output_is_severity_counts(self):
        with temp_dir() as tmp:
            write_run(tmp, sample())
            r = run_summary(tmp)
            self.assertEqual(r.returncode, 0, r.stderr)
            for line in ("Total: 4", "- critical: 1", "- high: 1", "- medium: 1", "- low: 1"):
                self.assertIn(line, r.stdout)
            self.assertNotIn("|", r.stdout)

    def test_list_prints_only_requested_severities(self):
        with temp_dir() as tmp:
            write_run(tmp, sample())
            r = run_summary(tmp, "--list", "critical", "high")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("(2)", r.stdout.splitlines()[0])
            self.assertIn("`app.py:4`", r.stdout)
            self.assertIn("`tools/a.py:7`", r.stdout)
            self.assertNotIn("tools/b.py", r.stdout)
            self.assertNotIn("tools/c.py", r.stdout)

    def test_list_never_prints_evidence(self):
        with temp_dir() as tmp:
            write_run(tmp, sample())
            r = run_summary(tmp, "--list", "critical", "high")
            self.assertNotIn("REDACTED", r.stdout)
            self.assertNotIn("raw tool output", r.stdout)

    def test_pipe_in_title_does_not_break_the_table(self):
        with temp_dir() as tmp:
            write_run(tmp, sample())
            out = run_summary(tmp, "--list", "high").stdout
            row = next(line for line in out.splitlines() if "semgrep" in line)
            self.assertIn("bad \\| thing", row)
            self.assertEqual(row.replace("\\|", "").count("|"), 5)

    def test_long_multiline_title_is_one_trimmed_line(self):
        with temp_dir() as tmp:
            write_run(tmp, [make_finding("high", "bandit", "x.py", 1, "word\n" * 100)])
            out = run_summary(tmp, "--list", "high").stdout
            rows = [line for line in out.splitlines() if line.startswith("| high")]
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0].rstrip().endswith("... |"))

    def test_no_matching_findings_says_none(self):
        with temp_dir() as tmp:
            write_run(tmp, [make_finding("low", "ruff")])
            r = run_summary(tmp, "--list", "critical", "high")
            self.assertEqual(r.returncode, 0)
            self.assertIn("(0)", r.stdout)
            self.assertIn("None.", r.stdout)

    def test_latest_run_is_used(self):
        with temp_dir() as tmp:
            write_run(tmp, [make_finding("low", "ruff")], name="old")
            time.sleep(0.05)
            write_run(tmp, sample(), name="new")
            os.utime(Path(tmp) / "reports" / "new", None)
            self.assertIn("Run: `new`", run_summary(tmp).stdout)

    def test_missing_reports_dir_is_an_error(self):
        with temp_dir() as tmp:
            r = run_summary(tmp, "--list", "high")
            self.assertEqual(r.returncode, 1)
            self.assertIn("no reports/ directory", r.stderr)

    def test_unknown_severity_is_rejected(self):
        with temp_dir() as tmp:
            write_run(tmp, sample())
            self.assertNotEqual(run_summary(tmp, "--list", "urgent").returncode, 0)


if __name__ == "__main__":
    unittest.main()
