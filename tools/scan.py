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
    fid = "sha1:" + hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:8]
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
    except Exception:                              # noqa: BLE001
        pass
    return None


def detect_pip_audit(project, log):
    """CVE в зависимостях Python. Требует pip-audit (в PATH или в текущем Python)."""
    base = _pip_audit_cmd()
    if base is None:
        log.write("  pip-audit not installed — skip\n")
        return []

    req = project / "requirements.txt"
    pyproj = project / "pyproject.toml"
    if req.exists():
        cmd = base + ["-r", str(req), "--format", "json",
                      "--progress-spinner", "off"]
    elif pyproj.exists():
        cmd = base + ["--path", str(project), "--format", "json",
                      "--progress-spinner", "off"]
    else:
        log.write("  no requirements.txt / pyproject.toml — skip\n")
        return []

    r = run(cmd, project, log, timeout=180)
    if r is None or not r.stdout:
        return []

    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []

    findings = []
    # pip-audit --format json: список пакетов, у каждого — vulns[]
    for pkg in data if isinstance(data, list) else data.get("dependencies", []):
        name = pkg.get("name", "?")
        version = pkg.get("version", "?")
        for v in pkg.get("vulns") or pkg.get("vulnerabilities") or []:
            vid = v.get("id", "?")
            fixes = v.get("fix_versions") or v.get("fixed_versions") or []
            desc = (v.get("description") or "").strip()
            severity = "medium" if fixes else "high"
            title = f"{name} {version} уязвим ({vid})"
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
                title=title,
                file="requirements.txt" if req.exists() else "pyproject.toml",
                line=0,
                evidence="\n".join(evidence_lines),
                detector="pip-audit",
            ))
    return findings


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
            findings.append(make_finding(
                category="vuln",
                severity="critical",
                title=f"Возможный секрет: {var} в {rel}:{i}",
                file=str(rel),
                line=i,
                # Значение НЕ показываем даже обрезанным — только факт наличия.
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


def detect_bandit(project, log):
    """bandit: типовые security-паттерны (eval, subprocess shell=True, и т.д.)."""
    base = _tool_cmd("bandit", "bandit")
    if base is None:
        log.write("  bandit not installed — skip\n")
        return []

    excl = ",".join([".git", "node_modules", ".venv", "venv",
                     "__pycache__", ".tox", "dist", "build"])
    cmd = base + ["-r", str(project), "-f", "json", "-q",
                  "--exclude", excl]
    r = run(cmd, project, log, timeout=180)
    if r is None or not r.stdout:
        return []

    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []

    sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    findings = []
    for item in data.get("results", []):
        sev = sev_map.get((item.get("issue_severity") or "").upper(), "low")
        text = (item.get("issue_text") or "").strip()
        title = text[:120] if text else item.get("test_name", "bandit issue")
        test_id = item.get("test_id", "")
        if test_id in ("B105", "B106", "B107"):
            m = re.search(r"""['"]([^'"]+)['"]""", text)
            if m:
                val = m.group(1)
                if ("/" in val or "\\" in val or val.startswith(".")
                        or val.endswith((".key", ".pem", ".crt", ".env"))):
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


RADON_SEV = {"A": None, "B": "low", "C": "medium",
             "D": "high", "E": "high", "F": "critical"}


def detect_radon(project, log):
    """radon: цикломатическая сложность > 10."""
    base = _tool_cmd("radon", "radon")
    if base is None:
        log.write("  radon not installed — skip\n")
        return []

    cmd = base + ["cc", "-s", "-j", str(project)]
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
        sev = "high" if item.get("severity") == "error" else "medium"
        code = item.get("code") or ""
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


def detect_pip_outdated(project, log):
    """pip list --outdated: устаревшие зависимости без CVE."""
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
    for item in data if isinstance(data, list) else []:
        name = item.get("name", "?")
        cur = item.get("version", "?")
        latest = item.get("latest_version", "?")
        # major bump — выше severity
        try:
            cur_major = int(str(cur).split(".")[0])
            new_major = int(str(latest).split(".")[0])
            sev = "medium" if new_major > cur_major else "low"
        except (ValueError, TypeError):
            sev = "low"
        findings.append(make_finding(
            category="improvement",
            severity=sev,
            title=f"{name}: {cur} → {latest}",
            file="requirements.txt",
            line=0,
            evidence=f"{name} {cur} -> {latest}",
            detector="pip-outdated",
        ))
    log.write(f"  total: {len(findings)}\n")
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


def detect_pyscn(project, log):
    """pyscn: дубли кода (clone detection), Type 1-4."""
    base = _tool_cmd("pyscn", "pyscn")
    if base is None:
        log.write("  pyscn not installed — skip (try: uvx pyscn)\n")
        return []
    cmd = base + ["analyze", "--json", "--select", "clones", "--no-open", str(project)]
    r = run(cmd, project, log, timeout=180)
    if r is None:
        return []
    # pyscn может писать JSON в stdout
    out = (r.stdout or "").strip()
    if not out.startswith("{"):
        log.write("  no json output (pyscn may have written to file)\n")
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []
    findings = []
    for clone in (data.get("clones") or data.get("duplicates") or []):
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
    cmd = base + ["scan", "--all-files", "--force-use-all-plugins"]
    r = run(cmd, project, log, timeout=180)
    if r is None or not r.stdout:
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        log.write(f"  json parse error: {e}\n")
        return []
    findings = []
    for fname, items in (data.get("results") or {}).items():
        for it in items or []:
            line = it.get("line_number", 0)
            stype = it.get("type", "Secret")
            findings.append(make_finding(
                category="vuln",
                severity="critical" if it.get("is_verified") else "high",
                title=f"{stype} в {fname}:{line}",
                file=_rel(project, fname),
                line=line,
                evidence=f"{stype} hashed={it.get('hashed_secret', '')[:16]}…",
                detector="detect-secrets",
            ))
    log.write(f"  total: {len(findings)}\n")
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


def run_detector(name, fn, project, log):
    log.write(f"\n[{name}]\n")
    try:
        findings = fn(project, log)
    except Exception as e:                       # noqa: BLE001
        log.write(f"  detector crashed: {e!r}\n")
        return []
    log.write(f"  → {len(findings)} findings\n")
    return findings


def slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "project"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", help="Путь к проекту")
    parser.add_argument("--out", default=None,
                        help="Каталог для отчётов (по умолчанию ./.scout)")
    parser.add_argument("--run-name", default=None,
                        help="Имя папки прогона (по умолчанию <дата>-<slug>)")
    args = parser.parse_args(argv)

    project = Path(args.project).resolve()
    if not project.is_dir():
        print(f"scout: не каталог: {project}", file=sys.stderr)
        return 2

    out_root = Path(args.out).resolve() if args.out else Path.cwd() / ".scout"
    out_root.mkdir(parents=True, exist_ok=True)

    date = datetime.now().strftime("%Y-%m-%d")
    run_name = args.run_name or f"{date}-{slugify(project.name)}"
    run_dir = out_root / run_name
    if run_dir.exists():
        i = 2
        while (out_root / f"{run_name}-{i}").exists():
            i += 1
        run_dir = out_root / f"{run_name}-{i}"
    run_dir.mkdir(parents=True)

    findings = []
    with open(run_dir / "scan.log", "w", encoding="utf-8") as log:
        log.write("scout scan\n")
        log.write(f"project: {project}\n")
        log.write(f"time:    {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
        log.write(f"python:  {find_project_python(project)}\n")

        for name, fn in DETECTORS:
            findings += run_detector(name, fn, project, log)

    findings.sort(key=lambda f: (
        SEVERITY_ORDER.get(f["severity"], 9),
        f["category"],
        f["file"],
        f["line"],
    ))

    (run_dir / "findings.json").write_text(
        json.dumps(findings, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"scout: {len(findings)} findings → {run_dir}")
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev):
            print(f"  {sev:<8} {counts[sev]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())