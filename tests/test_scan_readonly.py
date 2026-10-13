"""scan.py и scout.py целиком: находки, «только чтение» и автоматический diff."""
import json
import os
import unittest
from pathlib import Path

from _helpers import FAKE_KEY_LINE, TODO, load_tool, run_tool, snapshot, temp_dir

scan = load_tool("scan")


def make_project(root):
    proj = Path(root) / "proj"
    proj.mkdir()
    # Медленные сетевые детекторы тестам не нужны (а в CI самоскана они есть).
    (proj / ".scoutrc").write_text(
        '{"skip_detectors": ["semgrep", "pyscn"]}', encoding="utf-8")
    (proj / "app.py").write_text(
        f"{FAKE_KEY_LINE}\n\n\ndef f():\n    # {TODO}: handle errors\n    return 1\n",
        encoding="utf-8",
    )
    return proj


def last_run(out):
    runs = sorted(p for p in Path(out).iterdir() if (p / "findings.json").exists())
    return runs[-1]


class ScanEndToEndTest(unittest.TestCase):
    def setUp(self):
        self._tmp = temp_dir()
        self.tmp = Path(self._tmp.name)
        # Кэши инструментов уходят в тестовый каталог, а не в общий temp.
        self.env = {**os.environ, "SCOUT_CACHE_DIR": str(self.tmp / "cache")}

    def tearDown(self):
        self._tmp.cleanup()

    def test_builtin_detectors_find_secret_and_todo(self):
        proj = make_project(self.tmp)
        r = run_tool("scan.py", proj, "--out", self.tmp / "out", "--quick", env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        findings = json.loads((last_run(self.tmp / "out") / "findings.json").read_text("utf-8"))
        detectors = {f["detector"] for f in findings}
        self.assertTrue({"secrets", "todo-fixme"} <= detectors, detectors)
        secret = next(f for f in findings if f["detector"] == "secrets")
        self.assertEqual((secret["file"], secret["line"], secret["severity"]),
                         ("app.py", 1, "critical"))
        self.assertNotIn("sk-live-0123456789abcdef0123", json.dumps(findings),
                         "значение секрета не должно попадать в отчёт")

    def test_scan_does_not_write_into_the_project(self):
        # Регрессия: mypy/ruff/pytest оставляли .mypy_cache, .ruff_cache,
        # .pytest_cache и __pycache__ рядом с кодом.
        proj = make_project(self.tmp)
        (proj / "test_app.py").write_text(
            "from app import f\n\n\ndef test_f():\n    assert f() == 1\n", encoding="utf-8")
        before = snapshot(proj)
        r = run_tool("scan.py", proj, "--out", self.tmp / "out", env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(snapshot(proj), before)

    def test_tool_env_redirects_caches_outside_project(self):
        proj = self.tmp / "proj"
        os.environ["SCOUT_CACHE_DIR"] = str(self.tmp / "cache")
        try:
            env = scan.tool_env(proj)
        finally:
            del os.environ["SCOUT_CACHE_DIR"]
        cache = str(self.tmp / "cache")
        self.assertTrue(env["MYPY_CACHE_DIR"].startswith(cache))
        self.assertTrue(env["RUFF_CACHE_DIR"].startswith(cache))
        self.assertIn("cache_dir=", env["PYTEST_ADDOPTS"])
        self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")

    def test_user_pytest_addopts_are_preserved(self):
        os.environ["PYTEST_ADDOPTS"] = "-x"
        try:
            env = scan.tool_env(self.tmp / "proj")
        finally:
            del os.environ["PYTEST_ADDOPTS"]
        self.assertTrue(env["PYTEST_ADDOPTS"].startswith("-x "))

    def test_scoutrc_skip_detectors_is_applied(self):
        proj = make_project(self.tmp)
        (proj / ".scoutrc").write_text(
            '{"skip_detectors": ["todo-fixme", "semgrep", "pyscn"]}', encoding="utf-8")
        r = run_tool("scan.py", proj, "--out", self.tmp / "out", "--quick", env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        findings = json.loads((last_run(self.tmp / "out") / "findings.json").read_text("utf-8"))
        self.assertNotIn("todo-fixme", {f["detector"] for f in findings})
        self.assertIn("secrets", {f["detector"] for f in findings})

    def test_missing_project_exits_with_error(self):
        r = run_tool("scan.py", self.tmp / "nope", "--out", self.tmp / "out", env=self.env)
        self.assertEqual(r.returncode, 2)


class ScoutOneCommandTest(unittest.TestCase):
    def test_second_run_finds_previous_run_and_writes_diff(self):
        with temp_dir() as tmp:
            tmp = Path(tmp)
            env = {**os.environ, "SCOUT_CACHE_DIR": str(tmp / "cache")}
            proj = make_project(tmp)
            out = tmp / "out"

            first = run_tool("scout.py", proj, "--out", out, "--quick", "--no-open", env=env)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertFalse((out / "diff.json").exists())
            self.assertTrue((out / "dashboard.html").exists())
            self.assertIn("Прошлого прогона", first.stdout)

            # Исправляем: убираем TODO, секрет оставляем.
            (proj / "app.py").write_text(FAKE_KEY_LINE + "\n", encoding="utf-8")
            second = run_tool("scout.py", proj, "--out", out, "--quick", "--no-open", env=env)
            self.assertEqual(second.returncode, 0, second.stderr)
            diff = json.loads((out / "diff.json").read_text("utf-8"))
            self.assertEqual(diff["summary"]["fixed"], 1)
            self.assertGreaterEqual(diff["summary"]["same"], 1)

            html = (out / "dashboard.html").read_text("utf-8")
            self.assertIn("window.STATE=", html)

    def test_another_project_does_not_inherit_stale_diff(self):
        with temp_dir() as tmp:
            tmp = Path(tmp)
            env = {**os.environ, "SCOUT_CACHE_DIR": str(tmp / "cache")}
            out = tmp / "out"
            a = make_project(tmp)
            run_tool("scout.py", a, "--out", out, "--quick", "--no-open", env=env)
            run_tool("scout.py", a, "--out", out, "--quick", "--no-open", env=env)
            self.assertTrue((out / "diff.json").exists())

            b = tmp / "other"
            b.mkdir()
            (b / "x.py").write_text("x = 1\n", encoding="utf-8")
            r = run_tool("scout.py", b, "--out", out, "--quick", "--no-open", env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse((out / "diff.json").exists())


if __name__ == "__main__":
    unittest.main()
