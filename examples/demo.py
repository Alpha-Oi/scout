#!/usr/bin/env python3
"""Демо Scout: полный цикл за одну команду, без своего проекта.

Что делает:
  1. Создаёт во временной папке маленький учебный проект с типичными
     проблемами (секрет в коде, eval, shell=True, TODO, неиспользуемый импорт).
  2. Сканирует его, формулирует предложения, строит дашборд.
  3. "Чинит" учебный проект и сканирует повторно.
  4. Считает diff между двумя прогонами и пересобирает дашборд.

Свой проект и сам Scout не изменяются: всё пишется во временную папку.

Использование:
    python examples/demo.py            # весь цикл, путь к дашборду в конце
    python examples/demo.py --open     # то же + открыть дашборд в браузере
    python examples/demo.py --keep DIR # писать в DIR вместо временной папки
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"

# Ключ собран из частей: иначе сам Scout находил бы "секрет" в этом файле
# при самосканировании репозитория.
FAKE_KEY = "sk-live-" + "9f8a7b6c5d4e3f2a" + "1b0c9d8e7f6a5b4c"

TODO = "TO" + "DO"  # то же самое: чтобы маркер не попал в самоскан

BAD_APP = f'''import os
import subprocess

API_KEY = "{FAKE_KEY}"


def run(cmd):
    # {TODO}: validate input
    return subprocess.run(cmd, shell=True)


def load(expr):
    return eval(expr)
'''

FIXED_APP = f'''import ast
import os
import subprocess

API_KEY = os.environ["API_KEY"]


def run(cmd):
    # {TODO}: add timeout
    return subprocess.run(cmd, check=True)


def load(expr):
    return ast.literal_eval(expr)
'''


def run_tool(script, *args):
    """Запустить tools/<script> тем же интерпретатором, вернуть stdout."""
    cmd = [sys.executable, str(TOOLS / script), *map(str, args)]
    print("$ python tools/" + script + " " + " ".join(
        a.name if isinstance(a, Path) else str(a) for a in args))
    r = subprocess.run(cmd, capture_output=True, text=True, check=False,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        raise SystemExit(f"{script} завершился с кодом {r.returncode}")
    # scan.py рисует прогресс через \r - показываем только итоговые строки
    return r.stdout.replace("\r", "\n")


def show_tail(text, marker):
    """Напечатать вывод начиная с итоговой строки `marker`."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(marker) and "→" in line:
            print("\n".join(lines[i:]))
            return
    print(text)


def latest_run(reports):
    runs = sorted(p for p in reports.iterdir()
                  if p.is_dir() and (p / "findings.json").exists())
    return runs[-1]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--open", action="store_true", help="открыть дашборд в браузере")
    ap.add_argument("--keep", metavar="DIR", help="писать в DIR, не удалять")
    args = ap.parse_args()

    base = Path(args.keep).resolve() if args.keep else Path(tempfile.mkdtemp(prefix="scout-demo-"))
    base.mkdir(parents=True, exist_ok=True)
    project = base / "demo-project"
    reports = base / "reports"
    project.mkdir(exist_ok=True)

    print("== 1. Учебный проект с проблемами:", project)
    (project / "app.py").write_text(BAD_APP, encoding="utf-8")

    print("\n== 2. Первый скан")
    out = run_tool("scan.py", project, "--out", reports, "--quick", "--run-name", "run-1")
    show_tail(out, "scout:")
    first = reports / "run-1"
    show_tail(run_tool("propose.py", first), "proposals:")

    print("\n== 3. Чиним учебный проект и сканируем повторно")
    (project / "app.py").write_text(FIXED_APP, encoding="utf-8")
    out = run_tool("scan.py", project, "--out", reports, "--quick", "--run-name", "run-2")
    show_tail(out, "scout:")
    second = reports / "run-2"
    run_tool("propose.py", second)

    print("\n== 4. Diff между прогонами и дашборд")
    # Порядок важен: render.py читает diff.json, поэтому diff идёт первым.
    print(run_tool("diff.py", first, second))
    print(run_tool("render.py", second))
    dashboard = reports / "dashboard.html"
    shutil.copy(TOOLS / "dashboard.html", dashboard)
    print(run_tool("sync.py", reports))

    print("Готово. Дашборд:", dashboard)
    print("Открыть:  python -m webbrowser", dashboard.as_uri())
    if args.open:
        webbrowser.open(dashboard.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
