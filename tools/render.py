#!/usr/bin/env python3
"""Собрать state.js из findings.json (+ proposals.json, если есть)."""
import argparse
import json
import re
from datetime import datetime
from pathlib import Path


def _finding_task_md(f):
    """Markdown-задача для одиночной находки — скопировать в Claude Code."""
    lines = [
        f"# Scout: {f.get('title', '')}",
        "",
        f"**Файл:** `{f.get('file', '?')}:{f.get('line', 0)}`",
        f"**Детектор:** `{f.get('detector', '?')}`",
        f"**Категория:** {f.get('category', '?')}",
        f"**Severity:** {f.get('severity', '?')}",
    ]
    if f.get("evidence"):
        lines += ["", "## Evidence", "```", f["evidence"], "```"]
    if f.get("proposal"):
        lines += ["", "## Предложение Scout", f["proposal"]]
    lines += [
        "",
        "## Что нужно",
        f"1. Открой `{f.get('file', '?')}` вокруг строки {f.get('line', 0)}",
        "2. Разберись в причине и исправь",
        "3. Прогони тесты проекта",
        "4. Покажи diff",
        "",
        "_Не трогай другие находки из отчёта Scout._",
    ]
    return "\n".join(lines)


def _group_task_md(g):
    """Markdown-задача для группы находок (один код — много файлов)."""
    items = g.get("items", [])
    lines = [
        f"# Scout: {g.get('code', g.get('title', ''))} — {g.get('count', len(items))} мест",
        "",
        f"**Детектор:** `{g.get('detector', '?')}`",
        f"**Категория:** {g.get('category', '?')}",
        f"**Severity:** {g.get('severity', '?')}",
    ]
    if g.get("proposal"):
        lines += ["", "## Предложение Scout", g["proposal"]]

    code = (g.get("code") or "").strip()
    det = g.get("detector", "")
    if det == "ruff" and code:
        lines += [
            "",
            "## Готовый автофикс",
            "```",
            f"ruff check --select {code} --fix",
            "git diff  # проверить изменения",
            "```",
        ]

    lines += ["", f"## Все места ({len(items)})", "```"]
    for it in items[:200]:
        lines.append(f"{it.get('file', '?')}:{it.get('line', 0)}")
    if len(items) > 200:
        lines.append(f"... и ещё {len(items) - 200}")
    lines += ["```", "",
              "## Что нужно",
              "1. Открой каждое место из списка",
              "2. Исправь все",
              "3. Прогони тесты",
              "4. Покажи общий diff",
              "",
              "_Не трогай другие группы из отчёта Scout._"]
    return "\n".join(lines)


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


def load_diff(scout_root):
    """Прочитать diff.json, если он есть рядом со state.js."""
    path = scout_root / "diff.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not all(k in data for k in ("new_ids", "fixed_ids", "same_ids")):
        return None
    return data


def load_meta(run_dir):
    """Прочитать meta.json (project_root и пр.), если есть."""
    path = run_dir / "meta.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


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

    diff = load_diff(scout_root)
    diff_status_by_id = {}
    if diff:
        # moved перекрывает same — у переместившихся находок свой бейдж
        for fid in diff.get("moved_ids", []):
            diff_status_by_id[fid] = "moved"
        for fid in diff.get("new_ids", []):
            diff_status_by_id[fid] = "new"
        for fid in diff.get("fixed_ids", []):
            diff_status_by_id[fid] = "fixed"
        for fid in diff.get("same_ids", []):
            if fid not in diff_status_by_id:
                diff_status_by_id[fid] = "same"

    meta = load_meta(run_dir)
    state = {
        "run": {
            "started": datetime.now().astimezone().isoformat(timespec="seconds"),
            "run_dir": str(run_dir),
            "project_root": meta.get("project_root", ""),
            "findings_count": len(findings),
        },
        "summary": {"severities": counts, "categories": by_cat},
        "findings": [
            {**f,
             "proposal": proposals.get(f["id"], {}).get("proposal"),
             "risk":     proposals.get(f["id"], {}).get("risk"),
             "effort":   proposals.get(f["id"], {}).get("effort"),
             "diff_status": diff_status_by_id.get(f["id"]),
             "task_md":  _finding_task_md({
                 **f,
                 "proposal": proposals.get(f["id"], {}).get("proposal"),
             })}
            for f in findings
        ],
        "groups": [
            {**g, "task_md": _group_task_md(g)}
            for g in group_findings(findings, proposals)
        ],
        "diff": diff,
    }

    out = scout_root / "state.js"
    out.write_text(
        "window.STATE=" + json.dumps(state, ensure_ascii=False) + ";",
        encoding="utf-8",
    )
    print(f"state.js: {len(findings)} findings -> {out}")


if __name__ == "__main__":
    main()
