#!/usr/bin/env python3
"""Нарезать задачи из прогона в .scout-queue/pending/.

Читает findings.json + proposals.json, пишет task-<id>.md для каждой находки,
которая проходит фильтр по severity/detector. Идемпотентно — уже
существующие файлы не перезаписываются.

Использование:
    cd C:\\projects\\my-app
    python D:\\Development\\scout\\tools\\queue.py D:\\reports\\2026-09-19-my-app
    python ...queue.py <run> --severity medium --limit 10
    python ...queue.py <run> --detector mypy --severity all
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def slugify(s):
    s = re.sub(r"[^a-zA-Z0-9]+", "-", str(s).lower()).strip("-")
    return (s[:60] or "task")


def default_verify(project):
    """Разумный набор verify-команд по структуре проекта."""
    cmds = []
    if ((project / "pyproject.toml").exists()
            or (project / "pytest.ini").exists()
            or (project / "tests").is_dir()):
        cmds.append("python -m pytest -q")
    if (project / "pyproject.toml").exists() or (project / "setup.py").exists():
        cmds.append("python -m mypy .")
    cmds.append("ruff check .")
    return cmds


def build_task(finding, proposal, verify):
    fid = finding["id"]
    det = finding.get("detector", "?")
    code = finding.get("code") or det
    sev = finding.get("severity", "low")
    file = finding.get("file", "?")
    line = finding.get("line", 0)
    title = finding.get("title", "")
    evidence = finding.get("evidence", "")

    front = [
        "---",
        f"id: {fid}",
        f"detector: {det}",
        f"code: {code}",
        f"severity: {sev}",
        f"file: {file}",
        f"line: {line}",
        f"created_at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "verify:",
    ]
    for c in verify:
        front.append(f"  - {c}")
    front.append("---")

    body = [
        "",
        f"# Task: {code} in {file}:{line}",
        "",
        f"**Severity:** `{sev}` · **Detector:** `{det}`",
        "",
        "## Finding",
        "",
        title,
        "",
    ]
    if evidence:
        body += ["## Evidence", "", "```", evidence, "```", ""]
    if proposal:
        body += ["## Proposal (from Scout)", "", proposal, ""]
    body += [
        "## Instructions for Fixer",
        "",
        f"1. Открой `{file}` около строки {line}.",
        "2. Разберись в причине и сделай **минимальную** правку.",
        "3. Прогони верификацию:",
    ]
    for c in verify:
        body.append(f"   - `{c}`")
    body += [
        "4. Если всё зелёное — `git add` + `git commit` в текущей ветке:",
        "   `fix(<detector>): <короткое описание>`",
        "5. Перемести **этот** файл в `.scout-queue/done/` и напиши рядом",
        "   `result.json`:",
        "   ```json",
        '   {"status": "done", "commit": "<sha>", "notes": "<что сделал>"}',
        "   ```",
        "6. Если правка невозможна или verify падает:",
        "   - `git restore .`",
        "   - Перемести файл в `.scout-queue/rejected/`",
        "   - `result.json`: `{\"status\": \"rejected\", \"reason\": \"...\"}`",
        "",
        "_Не трогай файлы вне этой задачи._",
        "",
    ]
    return "\n".join(front) + "\n" + "\n".join(body)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("run_dir", help="Каталог прогона (findings.json + proposals.json)")
    ap.add_argument("--queue", default=".scout-queue", help="Корень очереди")
    ap.add_argument("--severity", default="high",
                    choices=["critical", "high", "medium", "low", "all"])
    ap.add_argument("--detector", default=None)
    ap.add_argument("--limit", type=int, default=0, help="0 = без лимита")
    ap.add_argument("--project", default=".", help="Корень проекта (для verify)")
    ap.add_argument("--dry", action="store_true", help="Только показать, что было бы создано")
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    queue_root = Path(args.queue).resolve()
    project = Path(args.project).resolve()

    f_file = run_dir / "findings.json"
    if not f_file.exists():
        print(f"нет {f_file}", file=sys.stderr)
        return 1
    findings = json.loads(f_file.read_text(encoding="utf-8"))

    proposals = {}
    p_file = run_dir / "proposals.json"
    if p_file.exists():
        for p in json.loads(p_file.read_text(encoding="utf-8")):
            proposals[p["id"]] = p

    thresh = -1 if args.severity == "all" else SEV_ORDER[args.severity]
    verify = default_verify(project)

    selected = []
    for f in findings:
        if SEV_ORDER.get(f.get("severity"), 9) > thresh:
            continue
        if args.detector and f.get("detector") != args.detector:
            continue
        selected.append(f)

    selected.sort(key=lambda f: (
        SEV_ORDER.get(f["severity"], 9),
        f.get("file", ""),
        f.get("line", 0),
    ))
    if args.limit:
        selected = selected[: args.limit]

    if not selected:
        print("queue: нечего добавлять (0 находок после фильтра)")
        return 0

    if args.dry:
        print(f"queue (dry): {len(selected)} задач")
        for f in selected:
            print(f"  [{f['severity']:<8}] {f.get('detector','?'):<14} "
                  f"{f.get('file','?')}:{f.get('line',0)}")
        return 0

    pending = queue_root / "pending"
    pending.mkdir(parents=True, exist_ok=True)

    written = 0
    for f in selected:
        tid = slugify(f["id"].replace("sha1:", ""))
        path = pending / f"task-{tid}.md"
        if path.exists():
            continue
        path.write_text(
            build_task(f, proposals.get(f["id"], {}).get("proposal"), verify),
            encoding="utf-8",
        )
        written += 1

    print(f"queue: {written} новых задач → {pending}")
    print(f"       verify: {verify}")
    if not written:
        print("       (все уже были в очереди)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())