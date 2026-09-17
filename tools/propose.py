#!/usr/bin/env python3
"""Сформулировать предложение по каждой находке.

Читает findings.json, пишет proposals.json.
Без LLM — правила детерминированные: одинаковые findings → одинаковые proposals.

Использование:
    python tools/propose.py <run_dir>
    python tools/propose.py D:/Development/scout-reports/2026-09-17-gptmemoryengine-2
"""

import argparse
import json
import re
from pathlib import Path


def propose_pip_audit(f):
    """CVE в Python-зависимости. Извлекаем пакет, версию и fix-версию."""
    title = f.get("title", "")
    evidence = f.get("evidence", "")

    m = re.match(r"(\S+)\s+(\S+)\s+уязвим", title)
    if not m:
        return None
    pkg, version = m.group(1), m.group(2)

    fix_m = re.search(r"Исправить в:\s*(.+)", evidence)
    if fix_m:
        fix = fix_m.group(1).strip()
        return {
            "proposal": (f"Обновить {pkg} с {version} до {fix} в requirements.txt. "
                         f"Проверить changelog пакета на breaking changes "
                         f"и прогнать тесты после обновления."),
            "risk": "medium",
            "effort": "S",
        }
    return {
        "proposal": (f"Исправленной версии {pkg} нет. Проверить, используется ли "
                     f"уязвимый путь в коде; если да — рассмотреть замену пакета "
                     f"или изоляцию вызова."),
        "risk": "high",
        "effort": "M",
    }


def propose_secrets(f):
    """Возможный секрет в коде."""
    where = f.get("file", "?")
    line = f.get("line", 0)
    return {
        "proposal": (f"Проверить {where}:{line} — если значение действительно "
                     f"секрет: перенести в .env, добавить .env в .gitignore, "
                     f"ротировать ключ у провайдера. Если это плейсхолдер — "
                     f"переименовать переменную или добавить в allowlist."),
        "risk": "medium",
        "effort": "S",
    }


def propose_pytest(f):
    """Упавший тест."""
    return {
        "proposal": (f"Запустить точечно: pytest --lf -v. Посмотреть traceback, "
                     f"определить причину — падение в коде или устаревший тест. "
                     f"Если тест устарел — обновить ассерт, если код сломан — "
                     f"починить код."),
        "risk": "low",
        "effort": "M",
    }


def propose_todo(f):
    """TODO / FIXME."""
    evidence = (f.get("evidence") or "").strip()
    where = f"{f.get('file', '?')}:{f.get('line', 0)}"
    return {
        "proposal": (f"Разобрать пометку в {where}: {evidence[:100]}. "
                     f"Либо реализовать, либо удалить — вечные TODO накапливают "
                     f"долг и мешают поиску."),
        "risk": "low",
        "effort": "S",
    }


def propose_default(f):
    return {
        "proposal": f"Требуется ручная оценка: {f.get('title', '')[:120]}",
        "risk": "low",
        "effort": "M",
    }


def propose_bandit(f):
    """bandit: подозрительный security-паттерн."""
    code = ""
    evidence = (f.get("evidence") or "").strip().split("\n", 1)[0]
    if evidence:
        code = evidence.split(" ", 1)[0]
    return {
        "proposal": (f"Разобрать {code or 'bandit'}-находку: {f.get('title', '')}. "
                     f"Проверить, эксплуатируется ли путь в проде; если да — "
                     f"заменить на безопасный API (subprocess без shell, "
                     f"yaml.safe_load, ast.literal_eval вместо eval)."),
        "risk": "medium",
        "effort": "M",
    }


def propose_vulture(f):
    """vulture: мёртвый код."""
    where = f"{f.get('file', '?')}:{f.get('line', 0)}"
    return {
        "proposal": (f"Проверить {where}: {f.get('title', '')}. Прогнать grep "
                     f"по проекту — не используется ли через getattr / "
                     f"reflection / entry points. Если нет — удалить."),
        "risk": "low",
        "effort": "S",
    }


def propose_radon(f):
    """radon: высокая цикломатическая сложность."""
    title = f.get("title", "")
    where = f"{f.get('file', '?')}:{f.get('line', 0)}"
    return {
        "proposal": (f"Разбить {title} в {where}. Вынести ветки в отдельные "
                     f"функции, покрыть каждую тестом, повторить radon."),
        "risk": "low",
        "effort": "M",
    }


def propose_ruff(f):
    """ruff: стиль, unused, подозрительные конструкции."""
    title = f.get("title", "")
    code = title.split(":", 1)[0].strip() if ":" in title else "?"
    where = f"{f.get('file', '?')}:{f.get('line', 0)}"
    return {
        "proposal": (f"Исправить {code} в {where}. Попробовать "
                     f"ruff check --fix, затем проверить diff — "
                     f"автофикс не всегда безопасен."),
        "risk": "low",
        "effort": "S",
    }


def propose_mypy(f):
    code = (f.get("evidence") or "").split(" ", 1)[0]
    where = f"{f.get('file', '?')}:{f.get('line', 0)}"
    return {
        "proposal": (f"Исправить ошибку типа {code} в {where}. "
                     f"Либо аннотировать правильным типом, либо добавить "
                     f"# type: ignore с объяснением, если это ложное срабатывание."),
        "risk": "medium",
        "effort": "M",
    }


def propose_pip_outdated(f):
    title = f.get("title", "")
    return {
        "proposal": (f"Обновить {title}. Проверить changelog на breaking changes, "
                     f"прогнать тесты. Для major bump — отдельный PR."),
        "risk": "low",
        "effort": "S",
    }


def propose_interrogate(f):
    where = f.get("file", "?")
    return {
        "proposal": (f"Добавить docstrings в {where}: {f.get('title', '')}. "
                     f"Google-style: Args, Returns, Raises. Для приватных "
                     f"функций достаточно однострочного описания."),
        "risk": "low",
        "effort": "M",
    }


def propose_pyscn(f):
    where = f"{f.get('file', '?')}:{f.get('line', 0)}"
    return {
        "proposal": (f"Разобрать дубль кода в {where}. Найти вторую копию "
                     f"(pyscn analyze --select clones), вынести общую логику "
                     f"в функцию или модуль, заменить обе копии вызовом."),
        "risk": "medium",
        "effort": "M",
    }


def propose_semgrep(f):
    rule = (f.get("evidence") or "").split(" ", 1)[0]
    where = f"{f.get('file', '?')}:{f.get('line', 0)}"
    return {
        "proposal": (f"Разобрать semgrep-правило {rule} в {where}. "
                     f"Проверить, эксплуатируется ли в проде; если да — "
                     f"переписать участок по рекомендации из сообщения правила."),
        "risk": "medium",
        "effort": "M",
    }


def propose_detect_secrets(f):
    where = f"{f.get('file', '?')}:{f.get('line', 0)}"
    return {
        "proposal": (f"Секрет в {where}. Немедленно ротировать значение "
                     f"у провайдера, перенести в .env, добавить .env в "
                     f".gitignore. Если значение уже в git-истории — "
                     f"использовать git filter-repo."),
        "risk": "high",
        "effort": "M",
    }


ROUTES = {
    "pip-audit": propose_pip_audit,
    "secrets": propose_secrets,
    "pytest-failed": propose_pytest,
    "todo-fixme": propose_todo,
    "bandit": propose_bandit,
    "vulture": propose_vulture,
    "radon": propose_radon,
    "ruff": propose_ruff,
    "mypy": propose_mypy,
    "pip-outdated": propose_pip_outdated,
    "interrogate": propose_interrogate,
    "pyscn": propose_pyscn,
    "semgrep": propose_semgrep,
    "detect-secrets": propose_detect_secrets,
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("run_dir", help="Каталог прогона (с findings.json)")
    args = p.parse_args()

    run_dir = Path(args.run_dir).resolve()
    findings_file = run_dir / "findings.json"
    if not findings_file.exists():
        print(f"findings.json not found in {run_dir}")
        return 1

    findings = json.loads(findings_file.read_text(encoding="utf-8"))

    SEV_TO_RISK = {"critical": "high", "high": "high",
                   "medium": "medium", "low": "low"}
    RISK_ORDER = {"low": 0, "medium": 1, "high": 2}

    proposals = []
    for f in findings:
        detector = f.get("detector", "")
        fn = ROUTES.get(detector, propose_default)
        prop = fn(f) or propose_default(f)
        sev_risk = SEV_TO_RISK.get(f.get("severity", "low"), "low")
        if RISK_ORDER[sev_risk] > RISK_ORDER.get(prop["risk"], 0):
            prop["risk"] = sev_risk
        proposals.append({
            "id": f["id"],
            "proposal": prop["proposal"],
            "risk": prop["risk"],
            "effort": prop["effort"],
        })

    out = run_dir / "proposals.json"
    out.write_text(json.dumps(proposals, ensure_ascii=False, indent=2),
                   encoding="utf-8")

    print(f"proposals: {len(proposals)} → {out}")
    for pr in proposals:
        print(f"  [{pr['risk']:<6}] {pr['proposal'][:80]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
