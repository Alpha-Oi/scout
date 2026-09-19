#!/usr/bin/env python3
"""Сравнить два прогона Scout. Записать diff.json рядом со state.js.

Сравнение по fingerprint, с учётом дубликатов: если один и тот же fp
встречается несколько раз в одном прогоне, это корректно учитывается
через сопоставление по количеству. Инварианты:

    same + new   == len(new_run)
    same + fixed == len(old_run)
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


def _group_by_fp(findings):
    """Сгруппировать находки по fingerprint. Возвращает {fp: [findings]}."""
    by_fp = {}
    for f in findings:
        fp = f.get("fingerprint") or f.get("id") or ""
        by_fp.setdefault(fp, []).append(f)
    return by_fp


def _soft_key(f):
    """Ключ без line — для сопоставления находок, сместившихся по строкам."""
    return (
        f.get("detector", ""),
        str(f.get("file", "")).replace("\\", "/"),
        f.get("title", ""),
    )


def compare(old, new):
    """Двухуровневое сопоставление:
       1. Точный fingerprint (быстро, честно).
       2. Fallback по (detector, file, title) для переместившихся.

    Инварианты:
       same + new   == len(new)
       same + fixed == len(old)
    """
    old_by_fp = _group_by_fp(old)
    new_by_fp = _group_by_fp(new)

    same_ids = []
    new_ids = []
    fixed_objs = []
    moved = []

    # --- 1. точный fingerprint ---
    all_fps = set(old_by_fp) | set(new_by_fp)
    leftover_old = []
    leftover_new = []
    for fp in all_fps:
        o = old_by_fp.get(fp, [])
        n = new_by_fp.get(fp, [])
        paired = min(len(o), len(n))
        for f in n[:paired]:
            same_ids.append(f["id"])
        for f in n[paired:]:
            leftover_new.append(f)
        for f in o[paired:]:
            leftover_old.append(f)

    # --- 2. soft-key matching для переместившихся ---
    old_by_soft = {}
    for f in leftover_old:
        old_by_soft.setdefault(_soft_key(f), []).append(f)

    used_old_ids = set()
    for f in leftover_new:
        k = _soft_key(f)
        candidates = old_by_soft.get(k, [])
        match = None
        for c in candidates:
            if c["id"] not in used_old_ids:
                match = c
                break
        if match:
            used_old_ids.add(match["id"])
            moved.append({
                "id": f["id"],
                "old_id": match["id"],
                "old_line": match.get("line", 0),
                "new_line": f.get("line", 0),
                "file": f.get("file", ""),
                "title": f.get("title", ""),
                "detector": f.get("detector", ""),
                "severity": f.get("severity", ""),
            })
            same_ids.append(f["id"])
        else:
            new_ids.append(f["id"])

    for f in leftover_old:
        if f["id"] not in used_old_ids:
            fixed_objs.append(f)

    return {
        "summary": {
            "new": len(new_ids),
            "fixed": len(fixed_objs),
            "same": len(same_ids),
            "moved": len(moved),
        },
        "new_ids": new_ids,
        "fixed_ids": [f["id"] for f in fixed_objs],
        "same_ids": same_ids,
        "moved_ids": [m["id"] for m in moved],
        "moved": moved,
        "fixed": fixed_objs,
    }




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

    result = compare(old, new)
    result["old_run"] = str(old_dir)
    result["new_run"] = str(new_dir)
    result["old_count"] = len(old)
    result["new_count"] = len(new)

    s = result["summary"]
    # Инварианты: same+new = len(new), same+fixed = len(old)
    if s["same"] + s["new"] != len(new):
        print(f"WARN: same+new={s['same'] + s['new']} != {len(new)}",
              file=sys.stderr)
    if s["same"] + s["fixed"] != len(old):
        print(f"WARN: same+fixed={s['same'] + s['fixed']} != {len(old)}",
              file=sys.stderr)

    out = out_dir / "diff.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    print(f"diff: new={s['new']} fixed={s['fixed']} same={s['same']} -> {out}")
    print(f"      {s['same']}+{s['new']}={s['same'] + s['new']} = {len(new)} (current)")
    print(f"      {s['same']}+{s['fixed']}={s['same'] + s['fixed']} = {len(old)} (previous)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
