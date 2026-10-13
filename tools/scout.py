#!/usr/bin/env python3
"""Scout одной командой: скан -> предложения -> diff -> дашборд -> открыть.

Запускает те же скрипты из tools/, что и ручной конвейер, в правильном порядке:
scan.py, propose.py, diff.py (если для проекта есть прошлый прогон), render.py,
sync.py. Ничего не пишет в сканируемый проект - только в каталог отчётов.

Использование:
    python tools/scout.py <путь к проекту>
    python tools/scout.py <проект> --out ./reports --quick
    python tools/scout.py <проект> --no-open        # не открывать браузер
"""
import argparse
import json
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

TOOLS = Path(__file__).resolve().parent


def _run_dirs(out_root):
    """Каталоги прогонов (с findings.json) в каталоге отчётов."""
    if not out_root.is_dir():
        return set()
    return {p for p in out_root.iterdir()
            if p.is_dir() and (p / "findings.json").exists()}


def _project_of(run_dir):
    """Путь к проекту из meta.json прогона или None."""
    try:
        data = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data.get("project_root") if isinstance(data, dict) else None


def _previous_run(out_root, project):
    """Самый свежий прошлый прогон этого же проекта или None."""
    same = [p for p in _run_dirs(out_root) if _project_of(p) == str(project)]
    return max(same, key=lambda p: p.stat().st_mtime, default=None)


def _tool(script, *args, quiet=False):
    """Запустить tools/<script> тем же интерпретатором. Возвращает код выхода."""
    cmd = [sys.executable, str(TOOLS / script), *map(str, args)]
    if not quiet:
        return subprocess.run(cmd, check=False).returncode
    r = subprocess.run(cmd, check=False, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
    return r.returncode


def _fail(step, code):
    print(f"scout: шаг {step} завершился с кодом {code}", file=sys.stderr)
    return code or 1


def _parse_args(argv):
    ap = argparse.ArgumentParser(
        description="Scout одной командой: скан, предложения, diff, дашборд.")
    ap.add_argument("project", help="Путь к проекту")
    ap.add_argument("--out", default=".scout",
                    help="Каталог для отчётов (по умолчанию ./.scout)")
    ap.add_argument("--quick", action="store_true",
                    help="Пропустить медленные детекторы (pytest, pip-audit)")
    ap.add_argument("--max-findings", type=int, default=None,
                    help="Общий потолок находок")
    ap.add_argument("--llm", action="store_true",
                    help="Предложения через LLM (см. propose.py)")
    ap.add_argument("--no-open", action="store_true",
                    help="Не открывать дашборд в браузере")
    return ap.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    project = Path(args.project).expanduser().resolve()
    out_root = Path(args.out).expanduser().resolve()

    before = _run_dirs(out_root)
    prev = _previous_run(out_root, project)

    scan_args = [project, "--out", out_root]
    if args.quick:
        scan_args.append("--quick")
    if args.max_findings is not None:
        scan_args += ["--max-findings", args.max_findings]
    code = _tool("scan.py", *scan_args)
    if code:
        return _fail("scan", code)

    new = _run_dirs(out_root) - before
    if len(new) != 1:
        print("scout: не удалось определить папку нового прогона", file=sys.stderr)
        return 1
    run_dir = new.pop()

    propose_args = [run_dir] + (["--llm"] if args.llm else [])
    code = _tool("propose.py", *propose_args, quiet=True)
    if code:
        return _fail("propose", code)

    # render.py читает diff.json из каталога отчётов: свежий diff нужен до него,
    # а устаревший (от другого проекта) мешает, поэтому его убираем.
    diff_file = out_root / "diff.json"
    if prev is not None:
        code = _tool("diff.py", prev, run_dir, quiet=True)
        if code:
            return _fail("diff", code)
    else:
        diff_file.unlink(missing_ok=True)

    code = _tool("render.py", run_dir, quiet=True)
    if code:
        return _fail("render", code)

    dashboard = out_root / "dashboard.html"
    shutil.copyfile(TOOLS / "dashboard.html", dashboard)
    code = _tool("sync.py", out_root, quiet=True)
    if code:
        return _fail("sync", code)

    print()
    if prev is not None:
        print(f"Сравнение с прошлым прогоном: {prev.name} (вкладка Diff в дашборде)")
    else:
        print("Прошлого прогона этого проекта нет, diff появится при следующем запуске.")
    print(f"Дашборд: {dashboard}")
    if not args.no_open:
        webbrowser.open(dashboard.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
