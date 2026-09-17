#!/usr/bin/env python3
"""Verify Scout's integrity. Run before any scan."""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED = [
    "SKILL.md",
    "AGENTS.md",
    "CLAUDE.md",
    "phases/0-preflight.md",
    "phases/1-scan.md",
    "phases/2-classify.md",
    "phases/3-propose.md",
    "phases/4-render.md",
    "tools/scan.py",
    "tools/propose.py",
    "tools/render.py",
    "tools/sync.py",
    "tools/dashboard.html",
]


def main() -> int:
    errors = []
    for rel in REQUIRED:
        if not (ROOT / rel).exists():
            errors.append("missing: " + rel)

    skill = ROOT / "SKILL.md"
    if skill.exists():
        text = skill.read_text(encoding="utf-8")
        if not text.startswith("---\n"):
            errors.append("SKILL.md: missing YAML frontmatter")
        else:
            head = text.split("---", 2)[1] if text.count("---") >= 2 else ""
            for key in ("name:", "description:"):
                if ("\n" + key) not in ("\n" + head):
                    errors.append("SKILL.md: missing " + key)

    for py in list((ROOT / "tools").glob("*.py")) + list((ROOT / "scripts").glob("*.py")):
        try:
            ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError as e:
            errors.append(str(py.relative_to(ROOT)) + ": syntax error line " + str(e.lineno) + ": " + e.msg)

    dash = ROOT / "tools" / "dashboard.html"
    if dash.exists():
        html = dash.read_text(encoding="utf-8")
        for marker in ("/*STATE-BEGIN*/", "/*STATE-END*/"):
            if marker not in html:
                errors.append("dashboard.html: missing marker " + marker)

    if errors:
        print("scout check: FAILED", file=sys.stderr)
        for e in errors:
            print("  - " + e, file=sys.stderr)
        return 1

    print("scout check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
