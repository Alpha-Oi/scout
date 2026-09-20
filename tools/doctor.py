#!/usr/bin/env python3
"""Scout doctor - check and install detector tools."""
import argparse
import importlib.util
import shutil
import subprocess
import sys

DETECTORS = [
    ("pytest-failed",  "pytest",         "pytest",         "pytest",         True),
    ("pip-audit",      "pip-audit",      "pip_audit",      "pip-audit",      True),
    ("pip-outdated",   None,             "pip",            None,             True),
    ("bandit",         "bandit",         "bandit",         "bandit",         True),
    ("ruff",           "ruff",           "ruff",           "ruff",           True),
    ("mypy",           "mypy",           "mypy",           "mypy",           True),
    ("vulture",        "vulture",        "vulture",        "vulture",        True),
    ("radon",          "radon",          "radon",          "radon",          True),
    ("interrogate",    "interrogate",    "interrogate",    "interrogate",    True),
    ("pyscn",          "pyscn",          "pyscn",          "uv: pyscn",      False),
    ("semgrep",        "semgrep",        "semgrep",        "semgrep",        False),
    ("detect-secrets", "detect-secrets", "detect_secrets", "detect-secrets", True),
    ("todo-fixme",     None,             None,             None,             True),
    ("secrets",        None,             None,             None,             True),
]


def which(name):
    return shutil.which(name) if name else None


def module_ok(mod):
    if not mod:
        return False
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


def check(label, command, module, spec, required):
    if not command and not module:
        return "built-in", None, None
    if which(command):
        return "ok", "PATH", None
    if module_ok(module):
        return "ok", "python -m", None
    return "missing", None, spec


def pip_install(spec):
    print("  $ python -m pip install " + spec)
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", spec],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode == 0:
        print("    [ok]")
        return True
    print("    [err] " + ((r.stderr or r.stdout or "")[:200]))
    return False


def uv_install(spec):
    name = spec.split(":", 1)[1].strip()
    print("  $ python -m uv tool install " + name)
    r = subprocess.run([sys.executable, "-m", "uv", "tool", "install", name],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode == 0:
        print("    [ok]")
        return True
    print("    [err] " + ((r.stderr or r.stdout or "")[:200]))
    return False


def install(spec):
    if not spec:
        return False
    if spec.startswith("uv:"):
        return uv_install(spec)
    return pip_install(spec)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    print("Scout doctor - detector check")
    print()
    print("{:<16} {:<10} {:<12} {}".format("detector", "status", "via", "required"))
    print("-" * 54)

    results = []
    for label, cmd, mod, spec, required in DETECTORS:
        status, method, install_spec = check(label, cmd, mod, spec, required)
        results.append((label, status, method, install_spec, required))
        req = "yes" if required else "no"
        mark = {"ok": "[ok]  ", "built-in": "[core]", "missing": "[MISS]"}.get(status, "[?]")
        print("{:<16} {}{:<5} {:<12} {}".format(
            label, mark, status, method or "", req))

    print()
    total = len(results)
    ready = sum(1 for _, s, _, _, _ in results if s in ("ok", "built-in"))
    print("Ready: {}/{} detectors".format(ready, total))

    missing = [(label, spec) for label, status, _, spec, _ in results
               if status == "missing"]

    if not missing:
        print("All detectors installed.")
        return 0

    print("Missing: " + ", ".join(m[0] for m in missing))

    if args.check:
        print("--check: nothing installed.")
        return 0

    if not args.yes:
        ans = input("Install missing? [y/N] ").strip().lower()
        if ans not in ("y", "yes", "д", "да"):
            print("Cancelled.")
            return 0

    ok = 0
    for label, spec in missing:
        print("[" + label + "]")
        if install(spec):
            ok += 1
    print("Installed: {}/{}".format(ok, len(missing)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
