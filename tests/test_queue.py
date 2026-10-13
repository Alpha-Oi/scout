"""queue.py: фильтры по severity/detector и идемпотентность."""
import json
import unittest
from pathlib import Path

from _helpers import make_finding, run_tool, temp_dir


def write_run(run_dir, findings):
    run_dir.mkdir(parents=True)
    (run_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")


def sample():
    return [
        make_finding("critical", "secrets", line=1),
        make_finding("high", "mypy", line=2),
        make_finding("medium", "ruff", line=3),
        make_finding("low", "todo-fixme", line=4),
    ]


class QueueTest(unittest.TestCase):
    def queued(self, tmp, *args):
        run = Path(tmp) / "run"
        if not run.exists():
            write_run(run, sample())
        queue = Path(tmp) / "q"
        r = run_tool("queue.py", run, "--queue", queue, "--project", tmp, *args)
        self.assertEqual(r.returncode, 0, r.stderr)
        return sorted(p.name for p in (queue / "pending").glob("task-*.md")) \
            if (queue / "pending").exists() else []

    def test_default_threshold_is_high_and_above(self):
        with temp_dir() as tmp:
            self.assertEqual(len(self.queued(tmp)), 2)

    def test_severity_all_selects_every_finding(self):
        # Регрессия: раньше порог был -1 и "all" не выбирал ничего.
        with temp_dir() as tmp:
            self.assertEqual(len(self.queued(tmp, "--severity", "all")), 4)

    def test_severity_low_equals_all(self):
        with temp_dir() as tmp:
            self.assertEqual(len(self.queued(tmp, "--severity", "low")), 4)

    def test_detector_filter(self):
        with temp_dir() as tmp:
            self.assertEqual(len(self.queued(tmp, "--severity", "all", "--detector", "mypy")), 1)

    def test_limit(self):
        with temp_dir() as tmp:
            self.assertEqual(len(self.queued(tmp, "--severity", "all", "--limit", "3")), 3)

    def test_rerun_is_idempotent(self):
        with temp_dir() as tmp:
            first = self.queued(tmp, "--severity", "all")
            second = self.queued(tmp, "--severity", "all")
            self.assertEqual(first, second)

    def test_dry_run_writes_nothing(self):
        with temp_dir() as tmp:
            self.assertEqual(self.queued(tmp, "--severity", "all", "--dry"), [])


if __name__ == "__main__":
    unittest.main()
