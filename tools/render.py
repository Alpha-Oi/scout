#!/usr/bin/env python3
"""Собрать state.js из findings.json (+ proposals.json, если есть)."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", help="Каталог прогона (с findings.json)")
    parser.add_argument("--scout-root", default=None,
                        help="Куда положить state.js (по умолчанию — родитель run_dir)")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).resolve()
    scout_root = (Path(args.scout_root).resolve() if args.scout_root
                  else run_dir.parent)

    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))

    proposals = {}
    p_file = run_dir / "proposals.json"
    if p_file.exists():
        for p in json.loads(p_file.read_text(encoding="utf-8")):
            proposals[p["id"]] = p

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_cat = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1

    state = {
        "run": {
            "started": datetime.now().astimezone().isoformat(timespec="seconds"),
            "run_dir": str(run_dir),
            "findings_count": len(findings),
        },
        "summary": {"severities": counts, "categories": by_cat},
        "findings": [
            {**f,
             "proposal": proposals.get(f["id"], {}).get("proposal"),
             "risk":     proposals.get(f["id"], {}).get("risk"),
             "effort":   proposals.get(f["id"], {}).get("effort")}
            for f in findings
        ],
    }

    out = scout_root / "state.js"
    out.write_text(
        "window.STATE=" + json.dumps(state, ensure_ascii=False) + ";",
        encoding="utf-8",
    )
    print(f"state.js: {len(findings)} findings -> {out}")


if __name__ == "__main__":
    main()
