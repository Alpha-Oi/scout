#!/usr/bin/env python3
"""Print a summary of the latest Scout run. For CI logs and the step summary.

    python tools/summary.py                    severity counts
    python tools/summary.py --list critical high
                                               table of findings of those severities
                                               (detector, file:line, title; never evidence)
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low")


def _cell(text, limit=140):
    """Text for one markdown table cell: one line, no pipes, trimmed."""
    one_line = " ".join(str(text).split()).replace("|", "\\|")
    return one_line if len(one_line) <= limit else one_line[:limit - 3] + "..."


def print_counts(latest, findings):
    c = Counter(f.get("severity", "low") for f in findings)
    print("## Scout self-scan")
    print(f"Run: `{latest.name}`")
    print(f"Total: {len(findings)}")
    for k in SEVERITIES:
        print(f"- {k}: {c.get(k, 0)}")


def print_findings(latest, findings, severities):
    picked = [f for f in findings if f.get("severity", "low") in severities]
    print(f"## Scout self-scan: {', '.join(severities)} findings ({len(picked)})")
    print(f"Run: `{latest.name}`")
    if not picked:
        print()
        print("None.")
        return
    print()
    print("| severity | detector | location | title |")
    print("|---|---|---|---|")
    for f in picked:
        location = f"{f.get('file', '?')}:{f.get('line', 0)}"
        print(f"| {f.get('severity', 'low')} | {_cell(f.get('detector', '?'))} "
              f"| `{_cell(location)}` | {_cell(f.get('title', ''))} |")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", nargs="+", choices=SEVERITIES, metavar="SEVERITY",
                    help="print a table of findings with these severities instead of counts")
    args = ap.parse_args(argv)

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
    if args.list:
        print_findings(latest, findings, args.list)
    else:
        print_counts(latest, findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
