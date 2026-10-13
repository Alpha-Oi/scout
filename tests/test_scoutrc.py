""".scoutrc: разбор и применение правил."""
import unittest
from pathlib import Path

from _helpers import load_tool, make_finding, temp_dir

scan = load_tool("scan")


class LoadScoutrcTest(unittest.TestCase):
    def load(self, text):
        with temp_dir() as tmp:
            if text is not None:
                (Path(tmp) / ".scoutrc").write_text(text, encoding="utf-8")
            return scan.load_scoutrc(Path(tmp))

    def test_missing_file_gives_empty_config(self):
        self.assertEqual(self.load(None), {})

    def test_trailing_commas_are_forgiven(self):
        cfg = self.load('{"skip_detectors": ["pyscn",], "max_findings": 5,}')
        self.assertEqual(cfg, {"skip_detectors": ["pyscn"], "max_findings": 5})

    def test_underscore_keys_are_comments(self):
        cfg = self.load('{"_comment": "noise", "skip_detectors": ["semgrep"]}')
        self.assertEqual(cfg, {"skip_detectors": ["semgrep"]})

    def test_broken_json_falls_back_to_empty(self):
        self.assertEqual(self.load("{not json"), {})

    def test_non_object_is_ignored(self):
        self.assertEqual(self.load("[1, 2]"), {})


class ApplyRulesTest(unittest.TestCase):
    def test_severity_rules_override_by_detector(self):
        findings = [make_finding("medium", "todo-fixme"), make_finding("medium", "ruff")]
        out = scan._apply_severity_rules(findings, {"severity_rules": {"todo-fixme": "low"}})
        self.assertEqual([f["severity"] for f in out], ["low", "medium"])

    def test_per_detector_cap_keeps_first_n_only_for_that_detector(self):
        findings = [make_finding(detector="ruff", line=i) for i in range(5)]
        findings += [make_finding(detector="mypy", line=i) for i in range(3)]
        out = scan._apply_per_detector_caps(findings, {"max_findings_per_detector": {"ruff": 2}})
        self.assertEqual(sum(f["detector"] == "ruff" for f in out), 2)
        self.assertEqual(sum(f["detector"] == "mypy" for f in out), 3)

    def test_global_cap_cli_wins_over_config(self):
        findings = [make_finding(line=i) for i in range(10)]
        out = scan._apply_max_findings(findings, 3, {"max_findings": 7})
        self.assertEqual(len(out), 3)

    def test_global_cap_from_config(self):
        findings = [make_finding(line=i) for i in range(10)]
        out = scan._apply_max_findings(findings, None, {"max_findings": 7})
        self.assertEqual(len(out), 7)


class SelectDetectorsTest(unittest.TestCase):
    def names(self, quick, config):
        active, _ = scan._select_detectors(quick, config)
        return {n for n, _f in active}

    def test_all_detectors_by_default(self):
        self.assertEqual(len(self.names(False, {})), len(scan.DETECTORS))

    def test_quick_skips_slow_detectors_only(self):
        full, quick = self.names(False, {}), self.names(True, {})
        self.assertEqual(full - quick, {"pytest-failed", "pip-audit"})

    def test_skip_detectors_from_config(self):
        self.assertNotIn("semgrep", self.names(False, {"skip_detectors": ["semgrep"]}))


if __name__ == "__main__":
    unittest.main()
