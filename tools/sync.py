#!/usr/bin/env python3
"""Вписать state.js внутрь dashboard.html между маркерами.

Использование:
    python tools/sync.py D:/Development/scout-reports
"""
import json
import sys
from pathlib import Path

BEGIN, END = "/*STATE-BEGIN*/", "/*STATE-END*/"


def main():
    scout_root = Path(sys.argv[1] if len(sys.argv) > 1 else ".scout").resolve()
    state_file = scout_root / "state.js"
    page_file = scout_root / "dashboard.html"

    if not state_file.exists():
        print(f"state.js not found: {state_file}")
        return 1
    if not page_file.exists():
        print(f"dashboard.html not found: {page_file}")
        print("Скопируйте tools/dashboard.html в эту папку.")
        return 1

    raw = state_file.read_text(encoding="utf-8")
    body = raw.split("=", 1)[1].strip().rstrip(";")
    try:
        json.loads(body)
    except json.JSONDecodeError as e:
        print(f"state.js invalid JSON: line {e.lineno}: {e.msg}")
        return 1

    page = page_file.read_text(encoding="utf-8")
    i, j = page.find(BEGIN), page.find(END)
    if i < 0 or j < 0:
        print("маркеры /*STATE-BEGIN*/ ... /*STATE-END*/ не найдены в dashboard.html")
        return 1

    payload = ("window.STATE="
               + json.dumps(json.loads(body), ensure_ascii=False).replace("</", "<\\/")
               + ";")
    new = page[:i + len(BEGIN)] + payload + page[j:]
    if new == page:
        print("snapshot уже актуален")
        return 0

    tmp = page_file.with_suffix(".html.tmp")
    tmp.write_text(new, encoding="utf-8")
    tmp.replace(page_file)
    print(f"snapshot -> {page_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
