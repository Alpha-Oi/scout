#!/usr/bin/env python3
"""Собрать state.js из findings.json (+ proposals.json, если есть)."""
import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def _extract_code(detector, f):
    """Ключ группы: обычно код правила (I001, F841, SIM115, PYSEC-...)."""
    title = (f.get("title") or "").strip()
    if detector == "ruff" and ":" in title:
        return title.split(":", 1)[0].strip()
    if detector == "bandit":
        ev = (f.get("evidence") or "").split("\n", 1)[0]
        return (ev.split(" ", 1)[0].strip() if ev else "bandit")
    if detector == "radon":
        m = re.search(r"\(([A-F])\)\s*$", title)
        return "radon:" + (m.group(1) if m else "?")
    if detector == "pip-audit":
        m = re.search(r"\(([A-Z]+-\d{4}-\d+)\)", title)
        return "pip-audit:" + (m.group(1) if m else "?")
    return detector


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def group_findings(findings, proposals):
    """Собрать группы по (detector, code). Внутри группы — находки, отсортированные."""
    buckets = {}
    for f in findings:
        key = f.get("detector", "?") + ":" + _extract_code(f.get("detector", ""), f)
        buckets.setdefault(key, []).append(f)

    groups = []
    for key, items in buckets.items():
        items_sorted = sorted(items, key=lambda x: (
            SEV_ORDER.get(x.get("severity", "low"), 9),
            x.get("file", ""),
            x.get("line", 0),
        ))
        worst = items_sorted[0]
        # proposal от первой находки в группе — предполагаем, что он одинаков
        prop = proposals.get(worst["id"], {})
        groups.append({
            "key": key,
            "detector": worst.get("detector", "?"),
            "code": _extract_code(worst.get("detector", ""), worst),
            "title": worst.get("title", ""),
            "category": worst.get("category", "?"),
            "severity": worst.get("severity", "low"),
            "count": len(items),
            "proposal": prop.get("proposal"),
            "risk": prop.get("risk"),
            "effort": prop.get("effort"),
            "items": [
                {
                    "id": x["id"],
                    "file": x.get("file", ""),
                    "line": x.get("line", 0),
                    "title": x.get("title", ""),
                }
                for x in items_sorted
            ],
        })

    # Сортировка групп: severity → count desc → key
    groups.sort(key=lambda g: (
        SEV_ORDER.get(g["severity"], 9),
        -g["count"],
        g["key"],
    ))
    return groups


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
        "groups": group_findings(findings, proposals),
    }

    out = scout_root / "state.js"
    out.write_text(
        "window.STATE=" + json.dumps(state, ensure_ascii=False) + ";",
        encoding="utf-8",
    )
    print(f"state.js: {len(findings)} findings -> {out}")


if __name__ == "__main__":
    main()
