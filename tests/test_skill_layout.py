"""Скилл как продукт: ссылки на инструменты живы, а установленная копия работает из любого каталога."""
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from _helpers import ROOT, TODO, temp_dir

DOCS_WITH_COMMANDS = ["SKILL.md", "CLAUDE.md", "AGENTS.md", *sorted(
    str(p.relative_to(ROOT)) for p in (ROOT / "phases").glob("*.md"))]
REF = re.compile(r"python\s+(?:<skill dir>/)?((?:tools|scripts)/[\w\-]+\.py)")
SKILL_FILES = ["SKILL.md", "AGENTS.md", "CLAUDE.md", "tools", "phases", "scripts"]


class SkillReferencesTest(unittest.TestCase):
    def test_every_script_mentioned_in_skill_docs_exists(self):
        missing = []
        for rel in DOCS_WITH_COMMANDS:
            text = (ROOT / rel).read_text(encoding="utf-8")
            for m in REF.finditer(text):
                if not (ROOT / m.group(1)).exists():
                    missing.append(f"{rel}: {m.group(1)}")
        self.assertEqual(missing, [])

    def test_skill_md_explains_paths_are_relative_to_skill_dir(self):
        # Установленный в чужой проект скилл запускается с cwd = проект пользователя.
        text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("relative to the directory that contains this SKILL.md", text)


class InstalledCopyTest(unittest.TestCase):
    def test_installed_skill_runs_from_a_foreign_working_directory(self):
        with temp_dir() as tmp:
            tmp = Path(tmp)
            skill = tmp / "userproj" / ".claude" / "skills" / "scout"
            skill.mkdir(parents=True)
            for name in SKILL_FILES:
                src = ROOT / name
                if src.is_dir():
                    shutil.copytree(src, skill / name,
                                    ignore=shutil.ignore_patterns("__pycache__"))
                else:
                    shutil.copy(src, skill / name)
            shutil.copy(ROOT / "tools" / "dashboard.html", skill / "tools" / "dashboard.html")
            (tmp / "userproj" / "a.py").write_text(f"# {TODO}: x\n", encoding="utf-8")

            env = {**os.environ, "SCOUT_CACHE_DIR": str(tmp / "cache")}
            check = subprocess.run(
                [sys.executable, str(skill / "scripts" / "verify-skill.py")],
                capture_output=True, text=True, check=False, cwd=tmp, env=env)
            self.assertEqual(check.returncode, 0, check.stderr)

            work = tmp / "workdir"
            work.mkdir()
            r = subprocess.run(
                [sys.executable, str(skill / "tools" / "scout.py"), str(tmp / "userproj"),
                 "--quick", "--no-open"],
                capture_output=True, text=True, check=False, cwd=work, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((work / ".scout" / "dashboard.html").exists(),
                            "отчёты должны уходить в ./.scout рабочего каталога")
            self.assertFalse((tmp / "userproj" / ".scout").exists(),
                             "в сканируемый проект отчёты попадать не должны")


if __name__ == "__main__":
    unittest.main()
