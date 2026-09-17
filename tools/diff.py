#!/usr/bin/env python3
"""Сравнить два прогона Scout. Записать diff.json рядом со state.js.

Сравнение по fingerprint — он стабилен для одной и той же находки между
запусками. Одинаковые — совпали. Исчезли — были в старом, нет в новом.
Новые — есть в новом, не было в старом.

Использование:
    python tools/diff.py <old_run> <new_run>
    python tools/diff.py D:/reports/2026-09-17-gptmemoryengine-2 D:/reports/2026-09-18-gptmemoryengine-3
"""

import argparse
import json
import sys
from pathlib import Path


def load_findings(run_dir):
    path = run_dir / "findings.json"
    if not path.exists():
        print(f"findings.json not found in {run_dir}", file=sys.stderr)
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"invalid findings.json in {run_dir}: {e}", file=sys.stderr)
        return None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("old_run", help="Предыдущий прогон")
    p.add_argument("new_run", help="Текущий прогон")
    p.add_argument("--out", default=None,
                   help="Куда писать diff.json (по умолчанию — родитель new_run)")
    args = p.parse_args()

    old_dir = Path(args.old_run).resolve()
    new_dir = Path(args.new_run).resolve()
    out_dir = Path(args.out).resolve() if args.out else new_dir.parent

    old = load_findings(old_dir)
    new = load_findings(new_dir)
    if old is None or new is None:
        return 1

    old_by_fp = {f["fingerprint"]: f for f in old}
    new_by_fp = {f["fingerprint"]: f for f in new}

    new_ids, fixed_objs, same_ids = [], [], []
    for fp, f in new_by_fp.items():
        if fp in old_by_fp:
            same_ids.append(f["id"])
        else:
            new_ids.append(f["id"])

    for fp, f in old_by_fp.items():
        if fp not in new_by_fp:
            fixed_objs.append(f)

    result = {
        "old_run": str(old_dir),
        "new_run": str(new_dir),
        "old_count": len(old),
        "new_count": len(new),
        "summary": {
            "new": len(new_ids),
            "fixed": len(fixed_objs),
            "same": len(same_ids),
        },
        "new_ids": new_ids,
        "fixed_ids": [f["id"] for f in fixed_objs],
        "same_ids": same_ids,
        "fixed": fixed_objs,
    }

    out = out_dir / "diff.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    print(f"diff: new={len(new_ids)} fixed={len(fixed_objs)} "
          f"same={len(same_ids)} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
