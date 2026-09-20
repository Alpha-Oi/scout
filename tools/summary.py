#!/usr/bin/env python3
"""Print severity summary from the latest Scout run. For CI step summary."""
import json
import sys
from collections import Counter
from pathlib import Path


def main():
    reports = Path("reports")
    if not reports.is_dir():
        print("no reports/ directory", file=sys.stderr)
        return 1
    runs = sorted(
        [p for p in reports.iterdir()
         if p.is_dir() and (p / "findings.json").exists()],
        key=lambda p: p.stat().st_mtime,
    )
    if not runs:
        print("no runs found in reports/", file=sys.stderr)
        return 1
    latest = runs[-1]
    findings = json.loads((latest / "findings.json").read_text(encoding="utf-8"))
    c = Counter(f.get("severity", "low") for f in findings)
    print("## Scout self-scan")
    print(f"Run: `{latest.name}`")
    print(f"Total: {len(findings)}")
    for k in ("critical", "high", "medium", "low"):
        print(f"- {k}: {c.get(k, 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
