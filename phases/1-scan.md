# Phase 1 - Scan

Purpose: run detectors, collect findings into a single JSON file.

## Run

    python tools/scan.py <project> --out <report_root>

Add --quick if the user asked for a fast pass, or if the project is
large and pytest would run for more than a couple of minutes.
--quick skips pytest-failed and pip-audit.

## What it does

- Walks the project, skipping node_modules, .git, dist, .venv,
  __pycache__ and other generated or service directories.
- Runs fourteen detectors in order: pytest-failed, pip-audit,
  pip-outdated, bandit, ruff, mypy, vulture, radon, interrogate,
  pyscn, semgrep, detect-secrets, todo-fixme, secrets.
- Writes run/findings.json (list of findings) and
  run/scan.log (full trace of every detector invocation).

## Detector contract

Every detector returns a list of findings. Each finding has:

    {
      "id": "sha1:abc123",
      "category": "bug|vuln|incomplete|improvement",
      "severity": "critical|high|medium|low",
      "title": "short human-readable line",
      "file": "relative/path",
      "line": 42,
      "evidence": "raw output, trimmed",
      "detector": "name",
      "detected_at": "ISO-8601 UTC",
      "fingerprint": "stable across runs"
    }

fingerprint is detector:file:line:title. It stays the same between
runs for the same underlying issue - that is what lets phase 2 tell
"new finding" from "same finding as last time".

## Failure modes

- Detector tool missing (e.g. pip-audit not installed): logged as
  "not installed - skip", no findings. Not an error.
- Detector crashes: logged, no findings, scan continues with the next.
- Project has no tests and no dependencies: two detectors return 0
  findings, that is a normal outcome, not a failure.

## Announce

One line: Сканирование готово: N находок. - then phase 2.
