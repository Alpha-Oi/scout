#!/usr/bin/env python3
"""Сформулировать предложение по каждой находке.

Читает findings.json, пишет proposals.json.
Без LLM — правила детерминированные: одинаковые findings → одинаковые proposals.

Использование:
    python tools/propose.py <run_dir>
    python tools/propose.py D:/Development/scout-reports/2026-09-17-gptmemoryengine-2
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
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
        "proposal": ("Запустить точечно: pytest --lf -v. Посмотреть traceback, "
                     "определить причину — падение в коде или устаревший тест. "
                     "Если тест устарел — обновить ассерт, если код сломан — "
                     "починить код."),
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


MYPY_STUB_NOTE = {"import-untyped", "import-not-found"}


def propose_mypy(f):
    code = (f.get("evidence") or "").split(" ", 1)[0]
    where = f"{f.get('file', '?')}:{f.get('line', 0)}"
    if code in MYPY_STUB_NOTE:
        return {
            "proposal": (f"{code} в {where}: у пакета нет .pyi-стабов. "
                         f"Добавить в pyproject.toml секцию [tool.mypy] "
                         f"с ignore_missing_imports = true, или установить "
                         f"пакет types-<name>, если он существует."),
            "risk": "low",
            "effort": "S",
        }
    if code == "assignment":
        return {
            "proposal": (f"Несовпадение типов в {where}. Частые причины: "
                         f"open() без mode=\"rb\" при последующей работе как "
                         f"с bytes; str вместо bytes в переменной, объявленной "
                         f"как bytes; неверная аннотация. Открыть строку, "
                         f"сравнить аннотацию с реальным значением."),
            "risk": "medium",
            "effort": "M",
        }
    if code == "operator":
        return {
            "proposal": (f"Неподдерживаемая операция в {where}. Обычно это "
                         f"сложение bytes и str. Определить, какой тип нужен, "
                         f"привести оба операнда к нему: .encode() для str → "
                         f"bytes или .decode() для bytes → str."),
            "risk": "medium",
            "effort": "S",
        }
    if code == "var-annotated":
        return {
            "proposal": (f"Добавить аннотацию переменной в {where}. "
                         f"Пустой список — list[<type>] с конкретным типом. "
                         f"Пустой словарь — dict[K, V]. Без аннотации mypy "
                         f"не может вывести тип из последующего использования."),
            "risk": "low",
            "effort": "S",
        }
    return {
        "proposal": (f"Исправить {code} в {where}. Либо правильная аннотация, "
                     f"либо # type: ignore с объяснением, если ложное срабатывание."),
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


# ---------------------------------------------------------------------------
# LLM proposals (optional, enabled by --llm)
# ---------------------------------------------------------------------------

LLM_SYSTEM = (
    "Ты — опытный Python-разработчик. По находке сканера отвечай строго JSON "
    "без markdown и комментариев:\n"
    '{"proposal": "...", "risk": "low|medium|high", "effort": "S|M|L"}\n'
    "proposal — одно конкретное действие на русском, 1-3 предложения, "
    "без вводных слов. Не пиши 'можно' или 'стоит рассмотреть' — "
    "пиши что именно сделать."
)

CACHE_FILE = Path(".scout-llm-cache.json")


def _detect_provider():
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/tags")
        with urllib.request.urlopen(req, timeout=1):
            return "ollama"
    except Exception:  # noqa: BLE001  (probing local Ollama; any error = unavailable)
        return None


def _cache_key(finding, provider):
    h = hashlib.sha1(
        (provider + "|" + finding.get("fingerprint", finding.get("id", "")))
        .encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    return h[:16]


def _load_cache():
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache):
    try:
        CACHE_FILE.write_text(
            json.dumps(cache, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError:
        pass


def _user_prompt(f):
    parts = [
        "Детектор: " + str(f.get("detector", "?")),
        "Категория: " + str(f.get("category", "?")),
        "Severity: " + str(f.get("severity", "?")),
        "Файл: " + str(f.get("file", "?")) + ":" + str(f.get("line", 0)),
        "Заголовок: " + str(f.get("title", "")),
    ]
    ev = (f.get("evidence") or "").strip()
    if ev:
        parts.append("Evidence:\n" + ev[:800])
    return "\n".join(parts)


def _parse_llm_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict):
        return None
    prop = (data.get("proposal") or "").strip()
    if not prop:
        return None
    return {
        "proposal": prop,
        "risk": data.get("risk") if data.get("risk") in ("low", "medium", "high") else "medium",
        "effort": data.get("effort") if data.get("effort") in ("S", "M", "L") else "M",
    }


def _call_anthropic(finding):
    key = os.environ["ANTHROPIC_API_KEY"]
    model = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-haiku-latest")
    body = json.dumps({
        "model": model,
        "max_tokens": 400,
        "system": LLM_SYSTEM,
        "messages": [{"role": "user", "content": _user_prompt(finding)}],
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body, method="POST",
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read().decode("utf-8"))
    text = "".join(c.get("text", "") for c in data.get("content", []))
    return _parse_llm_json(text)


def _call_openai(finding):
    key = os.environ["OPENAI_API_KEY"]
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": LLM_SYSTEM},
            {"role": "user", "content": _user_prompt(finding)},
        ],
        "response_format": {"type": "json_object"},
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body, method="POST",
        headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read().decode("utf-8"))
    text = data["choices"][0]["message"]["content"]
    return _parse_llm_json(text)


def _call_ollama(finding):
    model = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
    body = json.dumps({
        "model": model,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": LLM_SYSTEM},
            {"role": "user", "content": _user_prompt(finding)},
        ],
    }).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
        data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read().decode("utf-8"))
    text = (data.get("message") or {}).get("content", "")
    return _parse_llm_json(text)


PROVIDER_FN = {
    "anthropic": _call_anthropic,
    "openai": _call_openai,
    "ollama": _call_ollama,
}


def llm_propose(finding, provider, cache):
    key = _cache_key(finding, provider)
    if key in cache:
        return cache[key], True
    fn = PROVIDER_FN.get(provider)
    if fn is None:
        return None, False
    try:
        result = fn(finding)
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError,
            json.JSONDecodeError, OSError, TimeoutError) as e:
        print(f"    LLM error ({provider}): {type(e).__name__}: {e}",
              file=sys.stderr)
        return None, False
    if result is None:
        return None, False
    cache[key] = result
    return result, False


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
    p.add_argument("--llm", action="store_true",
                   help="Использовать LLM для предложений (Anthropic/OpenAI/Ollama)")
    p.add_argument("--llm-max", type=int, default=20,
                   help="Максимум LLM-запросов за прогон (по умолчанию 20)")
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

    provider = _detect_provider() if args.llm else None
    cache = _load_cache() if provider else {}
    llm_used = 0
    llm_cached = 0
    if args.llm:
        if provider:
            print(f"llm: provider={provider}, max={args.llm_max}", file=sys.stderr)
        else:
            print("llm: no provider found (ANTHROPIC_API_KEY / OPENAI_API_KEY / "
                  "Ollama on 127.0.0.1:11434) — falling back to rules",
                  file=sys.stderr)

    proposals = []
    for f in findings:
        detector = f.get("detector", "")
        fn = ROUTES.get(detector, propose_default)
        prop = fn(f) or propose_default(f)

        if provider:
            hit_cache = _cache_key(f, provider) in cache
            if hit_cache or llm_used < args.llm_max:
                llm_result, was_cached = llm_propose(f, provider, cache)
                if llm_result:
                    prop = llm_result
                    if was_cached:
                        llm_cached += 1
                    else:
                        llm_used += 1

        sev_risk = SEV_TO_RISK.get(f.get("severity", "low"), "low")
        if RISK_ORDER[sev_risk] > RISK_ORDER.get(prop["risk"], 0):
            prop["risk"] = sev_risk
        proposals.append({
            "id": f["id"],
            "proposal": prop["proposal"],
            "risk": prop["risk"],
            "effort": prop["effort"],
        })

    if provider:
        _save_cache(cache)
        print(f"llm: {llm_used} new + {llm_cached} cached = "
              f"{llm_used + llm_cached} of {len(findings)} findings",
              file=sys.stderr)

    out = run_dir / "proposals.json"
    out.write_text(json.dumps(proposals, ensure_ascii=False, indent=2),
                   encoding="utf-8")

    print(f"proposals: {len(proposals)} → {out}")
    for pr in proposals:
        print(f"  [{pr['risk']:<6}] {pr['proposal'][:80]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
