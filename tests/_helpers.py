"""Общие помощники тестов: загрузка tools/*.py и запуск CLI."""
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"

# Маркеры собраны из частей: иначе самоскан Scout находил бы их в тестах.
TODO = "TO" + "DO"
FAKE_KEY_LINE = "API_KEY" + ' = "' + "sk-live-" + "0123456789abcdef0123" + '"'  # pragma: allowlist secret


def load_tool(name):
    """Импортировать tools/<name>.py под уникальным именем.

    queue.py нельзя импортировать как `queue`: это затенило бы stdlib.
    """
    spec = importlib.util.spec_from_file_location(f"scout_tool_{name}", TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_tool(script, *args, env=None):
    """Запустить tools/<script> как CLI, вернуть CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(TOOLS / script), *map(str, args)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False, env=env,
    )


def make_finding(severity="low", detector="ruff", file="app.py", line=1,
                 title="t", fid=None):
    """Минимальная находка в формате findings.json."""
    fid = fid or f"sha1:{detector}{file}{line}{title}"[:20].replace(" ", "")
    return {
        "id": fid, "category": "improvement", "severity": severity,
        "title": title, "file": file, "line": line, "evidence": "e",
        "detector": detector, "detected_at": "2026-01-01T00:00:00Z",
        "fingerprint": f"{detector}:{file}:{line}:{title}",
    }


def temp_dir():
    """Каталог, который удалится вместе с объектом (используйте как контекст)."""
    return tempfile.TemporaryDirectory(prefix="scout-test-")


def snapshot(root):
    """Все пути под root (относительные), для проверки «ничего не появилось»."""
    return sorted(str(p.relative_to(root)) for p in Path(root).rglob("*"))
