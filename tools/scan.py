#!/usr/bin/env python3
"""Scout — сканер проекта. Только читает, никогда не пишет в проект.

Запускает детекторы, собирает находки в единый формат, пишет findings.json.
Не формулирует предложений — это фаза 3. Не рисует дашборд — это фаза 4.

Использование:
    python tools/scan.py <путь к проекту>
    python tools/scan.py D:/Development/skills/worktrees/skills-development
    python tools/scan.py <проект> --out D:/reports

Выход:
    <out>/<YYYY-MM-DD>-<slug>/findings.json   массив находок
    <out>/<YYYY-MM-DD>-<slug>/scan.log        что запускалось и что вернуло
    По умолчанию <out> = ./.scout (рядом с местом запуска, не в проекте).
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# --- конфигурация -----------------------------------------------------------

# Каталоги, которые не обходим: чужие, сгенерированные, служебные.
EXCLUDE_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", ".venv", "venv", "env", ".tox",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".scout", ".autopilot",
    "dist", "build", ".next", ".nuxt", "target", "out",
    "coverage", "htmlcov", ".idea", ".vscode",
}

# Расширения, которые считаем текстовыми и обходим в построчных детекторах.
TEXT_EXTS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".go", ".rs", ".rb", ".java", ".kt", ".swift",
    ".c", ".h", ".cpp", ".hpp", ".cs",
    ".md", ".rst", ".txt",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".sh", ".bash", ".ps1", ".psm1", ".bat", ".cmd",
    ".html", ".css", ".scss", ".sql",
}

# Файл больше этого — не читаем построчно: скорее всего, сгенерирован.
MAX_TEXT_BYTES = 1_000_000

TODO_PATTERN = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b[:\s\-]*(.*)$")

SECRET_PATTERN = re.compile(
    r"""(?ix)
    \b
    ( api[_-]?key
    | secret[_-]?key
    | access[_-]?token
    | auth[_-]?token
    | private[_-]?key
    | client[_-]?secret
    | password
    | passwd
    )
    \s* [:=] \s*
    ['"]?([^'"\s]{12,})['"]?
    """
)

# Значения, которые выглядят как заполнители, а не как секреты.
PLACEHOLDER = re.compile(
    r"""(?ix)^(
        x{3,} | \.{3,} | <.+> | \$\{.+?\} |
        your[_-] | change[_-]?me | placeholder | example |
        todo | fixme | none | null | redacted |
        \{\{.+\}\}
    )"""
)

FAILED_LINE = re.compile(r"^FAILED\s+(\S+?)(?:\s+-\s+(.*))?$", re.MULTILINE)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# --- утилиты ----------------------------------------------------------------

def make_finding(category, severity, title, file, line, evidence, detector):
    """Единый формат находки. fingerprint стабилен между прогонами."""
    fingerprint = f"{detector}:{file}:{line}:{title}"
    fid = "sha1:" + hashlib.sha1(
        fingerprint.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()[:8]
    return {
        "id": fid,
        "category": category,          # bug | vuln | incomplete | improvement
        "severity": severity,          # critical | high | medium | low
        "title": title,
        "file": str(file),
        "line": int(line),
        "evidence": evidence,
        "detector": detector,
        "detected_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
        "fingerprint": fingerprint,
    }


def run(cmd, cwd, log, timeout=180):
    """Запустить подпроцесс. Возвращает CompletedProcess или None."""
    log.write(f"$ {' '.join(str(c) for c in cmd)}\n  cwd={cwd}\n")
    try:
        r = subprocess.run(
            cmd, cwd=str(cwd),
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=timeout,
            check=False,
        )
        log.write(f"  exit={r.returncode}\n")
        if r.stderr:
            snippet = r.stderr.strip().splitlines()[-3:]
            log.write("  stderr: " + " | ".join(snippet) + "\n")
        return r
    except FileNotFoundError:
        log.write("  not found\n")
        return None
    except subprocess.TimeoutExpired:
        log.write(f"  timeout after {timeout}s\n")
        return None
    except Exception as e:                      # noqa: BLE001 — детектор не должен падать
        log.write(f"  error: {e!r}\n")
        return None


def iter_text_files(root):
    """Обойти текстовые файлы проекта, пропуская мусорные каталоги."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() not in TEXT_EXTS:
                continue
            try:
                if p.stat().st_size > MAX_TEXT_BYTES:
                    continue
            except OSError:
                continue
            yield p


def find_project_python(project):
    """Python проекта, если у него есть свой venv. Иначе — python скаута."""
    candidates = [
        project / ".venv" / "Scripts" / "python.exe",     # Windows
        project / ".venv" / "bin" / "python",             # Unix
        project / "venv" / "Scripts" / "python.exe",
        project / "venv" / "bin" / "python",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return sys.executable


# --- детекторы --------------------------------------------------------------

def detect_pytest_failed(project, log):
    """Упавшие тесты. Сначала --lf (быстро), иначе — полный прогон."""
    py = find_project_python(project)

    # Быстрый путь: только последние упавшие.
    r = run([py, "-m", "pytest", "--lf", "--tb=no", "-q", "--no-header"],
            project, log, timeout=120)
    if r is not None:
        combined = (r.stdout or "") + "\n" + (r.stderr or "")
        if "no previously failed tests" not in combined and "no tests ran" not in combined:
            findings = _parse_pytest_failures(combined)
            if findings:
                return findings

    # Медленный путь: полный прогон, с потолком по времени.
    r = run([py, "-m", "pytest", "--tb=no", "-q", "--no-header"],
            project, log, timeout=180)
    if r is None:
        return []
    combined = (r.stdout or "") + "\n" + (r.stderr or "")
    return _parse_pytest_failures(combined)


def _parse_pytest_failures(text):
    findings = []
    for m in FAILED_LINE.finditer(text):
        nodeid = m.group(1).strip()
        reason = (m.group(2) or "").strip()
        parts = nodeid.split("::")
        file = parts[0]
        test_name = "::".join(parts[1:]) if len(parts) > 1 else ""
        title = f"Упавший тест: {test_name or nodeid}"
        if reason:
            title = f"{title} — {reason[:80]}"
        findings.append(make_finding(
            category="bug",
            severity="high",
            title=title,
            file=file,
            line=0,                              # --tb=no прячет номер строки
            evidence=nodeid + (f"\n{reason}" if reason else ""),
            detector="pytest-failed",
        ))
    return findings


def _clip_evidence(text, limit=600, min_keep=200):
    """Обрезать evidence по последней точке в предложении, не по символу.

    Позволяет описанию из pip-audit уместиться целиком, если оно короткое,
    и не рвётся на середине слова, если длинное.
    """
    text = text.strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    last_dot = cut.rfind(". ")
    if last_dot >= min_keep:
        return cut[: last_dot + 1]
    return cut.rstrip() + " …"


def _pip_audit_cmd():
    """pip-audit может быть не в PATH — тогда зовём его через python -m."""
    if _which("pip-audit"):
        return ["pip-audit"]
    try:
        import importlib.util
        if importlib.util.find_spec("pip_audit") is not None:
            return [sys.executable, "-m", "pip_audit"]
    except Exception:  # noqa: BLE001,S110  (find_spec can raise; fall back to None.)
        pass
    return None


def _pip_audit_build_cmd(project, base, log):
    req = project / "requirements.txt"
    pyproj = project / "pyproject.toml"
    if req.exists():
        return base + ["-r", str(req), "--format", "json",
                       "--progress-spinner", "off"]
    if pyproj.exists():
        return base + ["--path", str(project), "--format", "json",
                       "--progress-spinner", "off"]
    log.write("  no requirements.txt / pyproject.toml \u2014 skip\n")
    return None


def _pip_audit_parse(data, project):
    req_exists = (project / "requirements.txt").exists()
    findings = []
    pkgs = data if isinstance(data, list) else data.get("dependencies", [])
    for pkg in pkgs:
        name = pkg.get("name", "?")
        version = pkg.get("version", "?")
        vulns = pkg.get("vulns") or pkg.get("vulnerabilities") or []
        for v in vulns:
            vid = v.get("id", "?")
            fixes = v.get("fix_versions") or v.get("fixed_versions") or []
            desc = (v.get("description") or "").strip()
            severity = "medium" if fixes else "high"
            evidence_lines = []
            if desc:
                evidence_lines.append(_clip_evidence(desc))
            if fixes:
                evidence_lines.append(f"Исправить в: {', '.join(fixes[:5])}")
            else:
                evidence_lines.append("Исправленной версии нет")
            findings.append(make_finding(
                category="vuln",
                severity=severity,
                title=f"{name} {version} уязвим ({vid})",
                file="requirements.txt" if req_exists else "pyproject.toml",
                line=0,
                evidence="\n".join(evidence_lines),
                detector="pip-audit",
            ))
    return findings


def detect_pip_audit(project, log):
    """CVE в зависимостях Python. Требует pip-audit (в PATH или в текущем Python)."""
    base = _pip_audit_cmd()
    if base is None:
        log.write("  pip-audit not installed \u2014 skip\n")
        return []

    cmd = _pip_audit_build_cmd(project, base, log)
    if cmd is None:
        return []

    r = run(cmd, project, log, timeout=180)
    if r is None or not r.stdout:
        return []

    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []

    return _pip_audit_parse(data, project)


def detect_todo(project, log):
    """TODO / FIXME / XXX / HACK в исходниках."""
    findings = []
    for path in iter_text_files(project):
        rel = path.relative_to(project)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            m = TODO_PATTERN.search(line)
            if not m:
                continue
            tag, rest = m.group(1), m.group(2).strip()
            title = rest if rest else f"{tag} без описания"
            if len(title) > 120:
                title = title[:117] + "..."
            severity = "medium" if tag == "FIXME" else "low"
            findings.append(make_finding(
                category="incomplete",
                severity=severity,
                title=title,
                file=str(rel),
                line=i,
                evidence=line.strip()[:200],
                detector="todo-fixme",
            ))
    log.write(f"  total: {len(findings)}\n")
    return findings


def detect_secrets(project, log):
    """Возможные секреты в исходниках. Консервативно, с плейсхолдер-фильтром."""
    findings = []
    for path in iter_text_files(project):
        rel = path.relative_to(project)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            m = SECRET_PATTERN.search(line)
            if not m:
                continue
            var, val = m.group(1), m.group(2)
            if len(val) < 12:
                continue
            if PLACEHOLDER.match(val):
                continue
            rel_s = str(rel)
            in_doc = _is_doc_path(rel_s)
            findings.append(make_finding(
                category="vuln",
                severity="low" if in_doc else "critical",
                title=("[docs] " if in_doc else "")
                      + f"Возможный секрет: {var} в {rel}:{i}",
                file=rel_s,
                line=i,
                evidence=f"{var} = [REDACTED]",
                detector="secrets",
            ))
    log.write(f"  total: {len(findings)}\n")
    return findings


def _module_available(name):
    """Есть ли модуль в текущем Python (без import)."""
    try:
        import importlib.util
        return importlib.util.find_spec(name) is not None
    except Exception:                              # noqa: BLE001
        return False


def _tool_cmd(tool, module):
    """Префикс команды: [tool] если в PATH, иначе [python, -m, module], иначе None."""
    if _which(tool):
        return [tool]
    if _module_available(module):
        return [sys.executable, "-m", module]
    return None


def _rel(project, fname):
    """Относительный путь от project, если возможно."""
    try:
        return str(Path(fname).relative_to(project))
    except (ValueError, TypeError):
        return str(fname)


# Правила, которые bandit выдаёт практически всегда и которые
# в большинстве проектов являются шумом. Отключаются по умолчанию.
BANDIT_DEFAULT_SKIP = [
    "B105",   # hardcoded_password_string — ловит даже '0', 'ok', пути
    "B106",   # hardcoded_password_funcarg
    "B107",   # hardcoded_password_default
    "B404",   # import subprocess — парный к B603/B607
    "B603",   # subprocess without shell — парный к B404
    "B607",   # partial executable path
    "B311",   # random — почти всегда не security
    "B110",   # try/except/pass — стиль, ловится ruff
    "B112",   # try/except/continue — стиль
]


def _bandit_build_cmd(project, base, skip):
    excl = ",".join([".git", "node_modules", ".venv", "venv",  # noqa: FLY002
                     "__pycache__", ".tox", "dist", "build"])
    cmd = base + ["-r", str(project), "-f", "json", "-q",
                  "--exclude", excl]
    if skip:
        cmd += ["--skip", ",".join(skip)]
    return cmd


def _bandit_pathy_false_positive(test_id, text):
    """B105/B106/B107 часто ловят пути ('./secret.key') вместо паролей."""
    if test_id not in ("B105", "B106", "B107"):
        return False
    m = re.search(r"""['"]([^'"]+)['"]""", text)
    if not m:
        return False
    val = m.group(1)
    return ("/" in val or "\\" in val or val.startswith(".")
            or val.endswith((".key", ".pem", ".crt", ".env")))


def _bandit_parse(data, project):
    sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    findings = []
    for item in data.get("results", []):
        sev = sev_map.get((item.get("issue_severity") or "").upper(), "low")
        text = (item.get("issue_text") or "").strip()
        title = text[:120] if text else item.get("test_name", "bandit issue")
        test_id = item.get("test_id", "")
        if _bandit_pathy_false_positive(test_id, text):
            continue
        evidence = (
            f"{item.get('test_id', '?')} {item.get('test_name', '')}\n"
            f"{text}"
        ).strip()
        findings.append(make_finding(
            category="vuln",
            severity=sev,
            title=title,
            file=_rel(project, item.get("filename", "")),
            line=item.get("line_number", 0),
            evidence=evidence,
            detector="bandit",
        ))
    return findings


def detect_bandit(project, log, config=None):
    """bandit: типовые security-паттерны (eval, subprocess shell=True, и т.д.)."""
    base = _tool_cmd("bandit", "bandit")
    if base is None:
        log.write("  bandit not installed \u2014 skip\n")
        return []

    config = config or {}
    skip = config.get("bandit_skip")
    if skip is None:
        skip = BANDIT_DEFAULT_SKIP
    log.write(f"  bandit skip rules: {','.join(skip)}\n")

    cmd = _bandit_build_cmd(project, base, skip)
    r = run(cmd, project, log, timeout=180)
    if r is None or not r.stdout:
        return []

    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []

    findings = _bandit_parse(data, project)
    log.write(f"  total: {len(findings)}\n")
    return findings


VULTURE_LINE = re.compile(r"^(.+?):(\d+): (.+?)(?: \((\d+)% confidence\))?\s*$")


def detect_vulture(project, log):
    """vulture: мёртвый код — неиспользуемые функции, переменные, импорты."""
    base = _tool_cmd("vulture", "vulture")
    if base is None:
        log.write("  vulture not installed — skip\n")
        return []

    cmd = base + [str(project), "--min-confidence", "80"]
    r = run(cmd, project, log, timeout=120)
    if r is None:
        return []

    findings = []
    for line in (r.stdout or "").splitlines():
        m = VULTURE_LINE.match(line.strip())
        if not m:
            continue
        fname, lineno, desc, conf = m.group(1), m.group(2), m.group(3), m.group(4)
        findings.append(make_finding(
            category="improvement",
            severity="low",
            title=desc[:120],
            file=_rel(project, fname),
            line=int(lineno),
            evidence=(desc + (f" ({conf}% confidence)" if conf else "")),
            detector="vulture",
        ))
    log.write(f"  total: {len(findings)}\n")
    return findings


RADON_SEV = {"A": None, "B": "low", "C": "low",
             "D": "medium", "E": "medium", "F": "high"}


def detect_radon(project, log):
    """radon: цикломатическая сложность > 10."""
    base = _tool_cmd("radon", "radon")
    if base is None:
        log.write("  radon not installed — skip\n")
        return []

    excl = ("*/node_modules/*,*/venv/*,*/.venv/*,*/.git/*,"
            "*/dist/*,*/build/*,*/.tox/*,*/__pycache__/*")
    cmd = base + ["cc", "-s", "-j", "-e", excl, str(project)]
    r = run(cmd, project, log, timeout=180)
    if r is None or not r.stdout:
        return []

    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []

    findings = []
    for fname, items in data.items():
        for item in (items or []):
            rank = item.get("rank", "A")
            sev = RADON_SEV.get(rank)
            if sev is None:
                continue
            complexity = item.get("complexity", 0)
            name = item.get("name", "?")
            kind = item.get("type", "block")
            findings.append(make_finding(
                category="improvement",
                severity=sev,
                title=f"{kind} '{name}' сложность {complexity} ({rank})",
                file=_rel(project, fname),
                line=item.get("lineno", 0),
                evidence=f"complexity={complexity} rank={rank} type={kind}",
                detector="radon",
            ))
    log.write(f"  total: {len(findings)}\n")
    return findings


RUFF_CATEGORY = {
    "S": "vuln",        # bandit-like
    "B": "bug",         # bugbear
}


def _ruff_category(code):
    # Bandit-derived rules: S101..S799 (S followed by a digit)
    if len(code) >= 2 and code[0] == "S" and code[1].isdigit():
        return "vuln"
    # Pyflakes: undefined names, unused vars
    if code.startswith("F") and len(code) >= 2 and code[1].isdigit():
        return "bug"
    # Bugbear: dangerous patterns
    if code.startswith("B") and len(code) >= 2 and code[1].isdigit():
        return "bug"
    # SIM, I, E, W, C, N, D, UP — style / simplification
    return "improvement"


def _ruff_severity(code):
    # Real security issues (bandit rules in ruff)
    if len(code) >= 2 and code[0] == "S" and code[1].isdigit():
        return "high"
    # Undefined / redefined names — real bugs
    if code in ("F821", "F811", "F823", "F822"):
        return "high"
    # Unused variable, blind except, resource leak
    if code in ("F841", "BLE001", "SIM115"):
        return "medium"
    # Bugbear
    if code.startswith("B") and len(code) >= 2 and code[1].isdigit():
        return "medium"
    # Import sort, style
    return "low"


def detect_ruff(project, log):
    """ruff: стиль, неиспользуемые импорты, подозрительные конструкции."""
    base = _tool_cmd("ruff", "ruff")
    if base is None:
        log.write("  ruff not installed — skip\n")
        return []

    cmd = base + ["check", "--output-format", "json", str(project)]
    r = run(cmd, project, log, timeout=120)
    if r is None or not r.stdout:
        return []

    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []

    findings = []
    for item in (data if isinstance(data, list) else []):
        code = item.get("code", "?")
        message = (item.get("message") or "").strip()
        loc = item.get("location") or {}
        row = loc.get("row", 0)
        findings.append(make_finding(
            category=_ruff_category(code),
            severity=_ruff_severity(code),
            title=f"{code}: {message[:100]}",
            file=_rel(project, item.get("filename", "")),
            line=row,
            evidence=f"{code} {message}",
            detector="ruff",
        ))
    log.write(f"  total: {len(findings)}\n")
    return findings


def detect_mypy(project, log):
    """mypy: статическая проверка типов. Формат --output json (JSON lines)."""
    base = _tool_cmd("mypy", "mypy")
    if base is None:
        log.write("  mypy not installed — skip\n")
        return []
    cmd = base + ["-O", "json", "--no-error-summary", "--no-pretty",
                  "--hide-error-context", str(project)]
    r = run(cmd, project, log, timeout=240)
    if r is None or not r.stdout:
        return []
    findings = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        code = item.get("code") or ""
        raw_sev = item.get("severity") or ""
        MYPY_NOTES = {
            "import-untyped", "import-not-found", "no-untyped-def",
            "no-untyped-call", "annotation-unchecked", "unused-ignore",
            "redundant-expr",
        }
        if code in MYPY_NOTES:
            sev = "low"
        elif raw_sev == "error":
            sev = "high"
        else:
            sev = "medium"
        msg = (item.get("message") or "").strip()
        title = f"{code}: {msg[:110]}" if code else msg[:120]
        findings.append(make_finding(
            category="bug",
            severity=sev,
            title=title,
            file=_rel(project, item.get("file", "")),
            line=item.get("line", 0),
            evidence=f"{code} {msg}".strip(),
            detector="mypy",
        ))
    log.write(f"  total: {len(findings)}\n")
    return findings


def _project_requirements(project):
    """Имена пакетов из requirements.txt (нормализованные)."""
    names = set()
    req = project / "requirements.txt"
    if not req.exists():
        return names
    for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)", line)
        if m:
            names.add(re.sub(r"[-_.]+", "-", m.group(1).lower()))
    return names


def detect_pip_outdated(project, log):
    """pip list --outdated, отфильтрованный по requirements.txt проекта."""
    req_names = _project_requirements(project)
    if not req_names:
        log.write("  no requirements.txt or empty - skip\n")
        return []
    cmd = [sys.executable, "-m", "pip", "list", "--outdated", "--format", "json"]
    r = run(cmd, project, log, timeout=120)
    if r is None or not r.stdout:
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []
    findings = []
    kept = 0
    for item in data if isinstance(data, list) else []:
        name = item.get("name", "?")
        norm = re.sub(r"[-_.]+", "-", name.lower())
        if norm not in req_names:
            continue
        kept += 1
        cur = item.get("version", "?")
        latest = item.get("latest_version", "?")
        try:
            cur_major = int(str(cur).split(".")[0])
            new_major = int(str(latest).split(".")[0])
            sev = "medium" if new_major > cur_major else "low"
        except (ValueError, TypeError):
            sev = "low"
        findings.append(make_finding(
            category="improvement",
            severity=sev,
            title=f"{name}: {cur} -> {latest}",
            file="requirements.txt",
            line=0,
            evidence=f"{name} {cur} -> {latest}",
            detector="pip-outdated",
        ))
    log.write(f"  total: {len(findings)} (of {len(data)} outdated in env)\n")
    return findings




def detect_interrogate(project, log):
    """interrogate: доля docstrings. Из JSON берём файлы с покрытием < 80%."""
    base = _tool_cmd("interrogate", "interrogate")
    if base is None:
        log.write("  interrogate not installed — skip\n")
        return []
    cmd = base + ["--json", "-q", str(project)]
    r = run(cmd, project, log, timeout=120)
    if r is None or not r.stdout:
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []
    findings = []
    for fname, info in (data.get("files") or {}).items():
        cov = info.get("total", info.get("coverage", 100))
        if cov >= 80:
            continue
        missing = info.get("missing", info.get("missing_count", 0))
        findings.append(make_finding(
            category="improvement",
            severity="low" if cov >= 50 else "medium",
            title=f"документации: {cov:.0f}% ({missing} пропущено)",
            file=_rel(project, fname),
            line=0,
            evidence=f"coverage={cov:.1f}% missing={missing}",
            detector="interrogate",
        ))
    log.write(f"  total: {len(findings)}\n")
    return findings


def _pyscn_cmd():
    """pyscn через PATH или через `python -m uv tool run pyscn`."""
    base = _tool_cmd("pyscn", "pyscn")
    if base is not None:
        return base
    try:
        import importlib.util
        if importlib.util.find_spec("uv") is not None:
            return [sys.executable, "-m", "uv", "tool", "run", "pyscn"]
    except Exception:  # noqa: BLE001,S110  (find_spec can raise; fall back to None.)
        pass
    return None


def _pyscn_parse(data, project):
    findings = []
    clones = data.get("clones") or data.get("duplicates") or []
    for clone in clones:
        sim = clone.get("similarity", 0)
        sev = "high" if sim >= 0.9 else "medium"
        locs = clone.get("locations") or clone.get("files") or []
        first = locs[0] if locs else {}
        fname = first.get("file") or first.get("filename") or "?"
        line = first.get("line") or first.get("start_line") or 0
        findings.append(make_finding(
            category="improvement",
            severity=sev,
            title=f"дубль кода, similarity {sim:.2f}",
            file=_rel(project, fname),
            line=line,
            evidence=f"clone similarity={sim:.2f} locations={len(locs)}",
            detector="pyscn",
        ))
    return findings


def detect_pyscn(project, log):
    """pyscn: дубли кода (clone detection), Type 1-4."""
    base = _pyscn_cmd()
    if base is None:
        log.write("  pyscn not installed - skip (try: uvx pyscn)\n")
        return []
    cmd = base + ["analyze", "--json", "--select", "clones", "--no-open",
                  str(project)]
    r = run(cmd, project, log, timeout=180)
    if r is None:
        return []
    out = (r.stdout or "").strip()
    if not out.startswith("{"):
        log.write("  no json output (pyscn may have written to file)\n")
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []
    findings = _pyscn_parse(data, project)
    log.write(f"  total: {len(findings)}\n")
    return findings


def detect_semgrep(project, log):
    """semgrep: SAST с auto-правилами."""
    base = _tool_cmd("semgrep", "semgrep")
    if base is None:
        log.write("  semgrep not installed — skip\n")
        return []
    cmd = base + ["scan", "--config", "auto", "--json", "--quiet",
                  "--no-git-ignore", str(project)]
    r = run(cmd, project, log, timeout=300)
    if r is None or not r.stdout:
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []
    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    findings = []
    for item in (data.get("results") or []):
        meta = item.get("extra", {}).get("metadata", {}) or {}
        raw_sev = str(meta.get("severity", item.get("extra", {}).get("severity", "INFO"))).upper()
        sev = sev_map.get(raw_sev, "low")
        rule_id = item.get("check_id", "?")
        msg = (item.get("extra", {}).get("message") or "").strip()
        findings.append(make_finding(
            category="vuln",
            severity=sev,
            title=f"{rule_id}: {msg[:100]}",
            file=_rel(project, item.get("path", "")),
            line=(item.get("start") or {}).get("line", 0),
            evidence=f"{rule_id} {msg}",
            detector="semgrep",
        ))
    log.write(f"  total: {len(findings)}\n")
    return findings


def detect_detect_secrets(project, log):
    """detect-secrets: секреты с энтропийным анализом (дополняет regex-сканер)."""
    base = _tool_cmd("detect-secrets", "detect_secrets")
    if base is None:
        log.write("  detect-secrets not installed — skip\n")
        return []
    excl = r"\\.venv|venv|node_modules|\\.git|__pycache__|\\.tox|dist|build|\\.mypy_cache|\\.pytest_cache"
    cmd = base + ["scan", "--all-files", "--force-use-all-plugins",
                  "--exclude-files", excl, str(project)]
    r = run(cmd, project, log, timeout=300)
    if r is None or not r.stdout:
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []
    SKIP_RE = re.compile(
        r"(?:^|[/\\])("
        r"\.venv|venv|node_modules|\.git|__pycache__|\.tox|dist|build|"
        r"\.mypy_cache|\.pytest_cache|\.ruff_cache|"
        r"\.github[/\\]workflows|"
        r"chrome_profile|CachedData|Code Cache|GPUCache|"
        r"Cache|Cookies|History|Web Data|Local State|Preferences|"
        r"TransportSecurity|BrowsingTopicsState|leveldb"
        r")(?:[/\\]|$)",
        re.IGNORECASE,
    )

    findings = []
    kept = 0
    skipped = 0
    for fname, items in (data.get("results") or {}).items():
        norm = fname.replace("\\", "/")
        if SKIP_RE.search("/" + norm):
            skipped += len(items or [])
            continue
        for it in items or []:
            kept += 1
            line = it.get("line_number", 0)
            stype = it.get("type", "Secret")
            findings.append(make_finding(
                category="vuln",
                severity=("critical" if it.get("is_verified")
                          else ("medium" if stype == "Secret Keyword" else "high")),
                title=f"{stype} в {fname}:{line}",
                file=_rel(project, fname),
                line=line,
                evidence=f"{stype} hashed={it.get('hashed_secret', '')[:16]}...",
                detector="detect-secrets",
            ))
    log.write(f"  total: {len(findings)} (skipped {skipped} from caches/profiles)\n")
    return findings


def _which(name):
    from shutil import which
    return which(name)


# --- точка входа ------------------------------------------------------------

DETECTORS = [
    ("pytest-failed",   detect_pytest_failed),
    ("pip-audit",       detect_pip_audit),
    ("pip-outdated",    detect_pip_outdated),
    ("bandit",          detect_bandit),
    ("ruff",            detect_ruff),
    ("mypy",            detect_mypy),
    ("vulture",         detect_vulture),
    ("radon",           detect_radon),
    ("interrogate",     detect_interrogate),
    ("pyscn",           detect_pyscn),
    ("semgrep",         detect_semgrep),
    ("detect-secrets",  detect_detect_secrets),
    ("todo-fixme",      detect_todo),
    ("secrets",         detect_secrets),
]


def run_detector(name, fn, project, log, idx=None, total=None, config=None):
    """Запустить детектор в фоне, показывая живой счётчик времени."""
    prefix = f"[{idx}/{total}]" if idx and total else "[·]"
    pad = max(0, 18 - len(name))
    header = f"  {prefix} {name}{' ' * pad}"
    t0 = time.monotonic()
    log.write(f"\n[{name}]\n")

    result = {"findings": [], "error": None}

    def worker():
        try:
            # детекторы, принимающие config (bandit), вызываются с ним
            try:
                result["findings"] = fn(project, log, config) or []
            except TypeError:
                result["findings"] = fn(project, log) or []
        except Exception as e:                   # noqa: BLE001
            result["error"] = e

    th = threading.Thread(target=worker, daemon=True)
    th.start()

    # Живой счётчик: обновляем строку каждые 0.1с
    while th.is_alive():
        elapsed = time.monotonic() - t0
        print(f"\r{header}  {elapsed:>5.1f}s ...", end="", flush=True)
        time.sleep(0.1)
    th.join()

    elapsed = time.monotonic() - t0
    err = result["error"]
    if err is not None:
        log.write(f"  detector crashed: {err!r}\n")
        print(f"\r{header}crash  ({elapsed:.1f}s)")
        return []

    findings = result["findings"]
    log.write(f"  → {len(findings)} findings\n")
    n = len(findings)
    suffix = "finding" if n == 1 else "findings"
    print(f"\r{header}{n:>3} {suffix}  ({elapsed:>5.1f}s)")
    return findings

def _strip_keys(obj):
    """Удалить ключи, начинающиеся с _ или __, рекурсивно. Позволяет
    писать комментарии в .scoutrc как "_comment": "..."."""
    if isinstance(obj, dict):
        return {k: _strip_keys(v) for k, v in obj.items()
                if not str(k).startswith("_")}
    if isinstance(obj, list):
        return [_strip_keys(v) for v in obj]
    return obj


def load_scoutrc(project):
    """Прочитать .scoutrc из корня проекта. Возвращает dict или {}."""
    path = project / ".scoutrc"
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
        # убираем висячие запятые (JSON5-стиль)
        raw = re.sub(r",(\s*[}\]])", r"\1", raw)
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        print(f"scout: .scoutrc parse error: {e}", file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        return {}
    return _strip_keys(data)


DOC_PATHS_RE = re.compile(
    r"\.(md|rst|txt)$"
    r"|[/\\]docs?[/\\]"
    r"|[/\\]examples?[/\\]"
    r"|[/\\]fixtures?[/\\]"
    r"|README|CHANGELOG|LICENSE|SKILL\.md",
    re.IGNORECASE,
)


def _is_doc_path(rel):
    return bool(DOC_PATHS_RE.search(str(rel)))


def slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "project"


def _parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", help="Путь к проекту")
    parser.add_argument("--out", default=None,
                        help="Каталог для отчётов (по умолчанию ./.scout)")
    parser.add_argument("--run-name", default=None,
                        help="Имя папки прогона (по умолчанию <дата>-<slug>)")
    parser.add_argument("--quick", action="store_true",
                        help="Пропустить медленные детекторы (pytest, pip-audit)")
    parser.add_argument("--max-findings", type=int, default=None,
                        help="Общий потолок находок (по умолчанию без лимита)")
    return parser.parse_args(argv)


def _resolve_project(path):
    project = Path(path).resolve()
    if not project.is_dir():
        print(f"scout: не каталог: {project}", file=sys.stderr)
        return None
    return project


def _resolve_run_dir(out_arg, run_name_arg, project):
    out_root = Path(out_arg).resolve() if out_arg else Path.cwd() / ".scout"
    out_root.mkdir(parents=True, exist_ok=True)
    date = datetime.now().astimezone().strftime("%Y-%m-%d")
    run_name = run_name_arg or f"{date}-{slugify(project.name)}"
    run_dir = out_root / run_name
    if run_dir.exists():
        i = 2
        while (out_root / f"{run_name}-{i}").exists():
            i += 1
        run_dir = out_root / f"{run_name}-{i}"
    run_dir.mkdir(parents=True)
    return run_dir


def _select_detectors(quick, config):
    skip = {"pytest-failed", "pip-audit"} if quick else set()
    skip_cfg = set(config.get("skip_detectors") or [])
    active = [(n, f) for n, f in DETECTORS
              if n not in skip and n not in skip_cfg]
    return active, skip_cfg


def _announce_scan(project, active, quick, log, skip_cfg):
    log.write("scout scan\n")
    log.write(f"project: {project}\n")
    log.write(f"time:    {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
    log.write(f"python:  {find_project_python(project)}\n")
    if skip_cfg:
        log.write(f"skipped by .scoutrc: {sorted(skip_cfg)}\n")
    total = len(active)
    print(f"\nscout: scanning {project}\n")
    print(f"       detectors: {total}" + ("  (--quick)" if quick else ""))
    print()


def _run_all_detectors(active, project, log, config):
    findings = []
    total = len(active)
    for idx, (name, fn) in enumerate(active, 1):
        findings += run_detector(name, fn, project, log, idx, total, config)
    print()
    return findings


def _apply_severity_rules(findings, config):
    sev_rules = config.get("severity_rules") or {}
    if not sev_rules:
        return findings
    for f in findings:
        if f["detector"] in sev_rules:
            f["severity"] = sev_rules[f["detector"]]
    return findings


def _apply_per_detector_caps(findings, config):
    caps = config.get("max_findings_per_detector") or {}
    if not caps:
        return findings
    by_det = {}
    kept = []
    for f in findings:
        d = f["detector"]
        cap = caps.get(d)
        if cap is None:
            kept.append(f)
            continue
        by_det.setdefault(d, 0)
        if by_det[d] < int(cap):
            kept.append(f)
            by_det[d] += 1
    return kept


def _sort_findings(findings):
    findings.sort(key=lambda f: (
        SEVERITY_ORDER.get(f["severity"], 9),
        f["category"],
        f["file"],
        f["line"],
    ))
    return findings


def _apply_max_findings(findings, cli_cap, config):
    cap = cli_cap if cli_cap is not None else config.get("max_findings")
    if cap is None or len(findings) <= cap:
        return findings
    per_det_cap = max(cap // 2, 20)
    counts = {}
    kept = []
    for f in findings:
        d = f["detector"]
        if counts.get(d, 0) >= per_det_cap:
            continue
        kept.append(f)
        counts[d] = counts.get(d, 0) + 1
        if len(kept) >= cap:
            break
    dropped = len(findings) - len(kept)
    print(f"scout: capped at {cap} findings (dropped {dropped}, "
          f"per-detector max {per_det_cap})")
    return kept


def _write_findings(run_dir, findings, project):
    (run_dir / "findings.json").write_text(
        json.dumps(findings, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (run_dir / "meta.json").write_text(
        json.dumps({"project_root": str(project)}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _print_summary(findings, run_dir, elapsed):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"scout: {len(findings)} findings \u2192 {run_dir}  ({elapsed:.1f}s)")
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev):
            print(f"  {sev:<8} {counts[sev]}")


def main(argv=None):
    args = _parse_args(argv)
    project = _resolve_project(args.project)
    if project is None:
        return 2
    run_dir = _resolve_run_dir(args.out, args.run_name, project)
    config = load_scoutrc(project)
    t_start = time.monotonic()
    active, skip_cfg = _select_detectors(args.quick, config)
    with open(run_dir / "scan.log", "w", encoding="utf-8") as log:
        _announce_scan(project, active, args.quick, log, skip_cfg)
        findings = _run_all_detectors(active, project, log, config)
    findings = _apply_severity_rules(findings, config)
    findings = _apply_per_detector_caps(findings, config)
    findings = _sort_findings(findings)
    findings = _apply_max_findings(findings, args.max_findings, config)
    _write_findings(run_dir, findings, project)
    _print_summary(findings, run_dir, time.monotonic() - t_start)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())