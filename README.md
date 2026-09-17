# Scout

Read-only project scanner with a dashboard.

Scout walks a project, runs a set of detectors, and produces a single HTML
dashboard with every finding — bug, vulnerability, unfinished work, or
improvement opportunity. For each finding it proposes one concrete action.

Scout never edits the scanned project. It only reports.

## What it finds

| Detector | Category | What it detects |
|---|---|---|
| `pytest-failed` | bug | Failing tests from the last pytest run |
| `pip-audit` | vuln | Known CVEs in Python dependencies |
| `todo-fixme` | incomplete | TODO / FIXME / XXX / HACK markers |
| `secrets` | vuln | Possible API keys, tokens, passwords in source |

Missing tools are skipped, not faked. If `pip-audit` is not installed, the
detector logs `not installed - skip` and the scan continues.

## Install

    git clone https://github.com/Alpha-Oi/scout.git
    cd scout
    python scripts/verify-skill.py

Requirements: Python 3.11+. Optional: `pip-audit` for the CVE detector,
`pytest` for the failing-tests detector.

    python -m pip install pip-audit pytest

## Run

Scan a project and open the dashboard:

    python tools/scan.py <path-to-project> --out ./reports
    python tools/propose.py ./reports/<run-dir>
    python tools/render.py ./reports/<run-dir>
    python tools/sync.py ./reports
    start ./reports/dashboard.html

Or, in Claude Code / Cursor / Codex:

    /scout <path-to-project>

## Layout

    SKILL.md                 the skill itself (phases, rules)
    phases/                  one file per phase, read at phase start
    tools/                   the runtime: Python scripts + dashboard.html
    scripts/                 verify-skill.py, build-adapters.py
    AGENTS.md, CLAUDE.md     adapters for Codex and Claude Code
    .cursor/rules/scout.mdc  adapter for Cursor

Reports go to a directory you choose (default `./.scout`), never inside
the scanned project.

## Detector contract

Every finding is a JSON object:

```json
{
  "id": "sha1:abc123",
  "category": "bug|vuln|incomplete|improvement",
  "severity": "critical|high|medium|low",
  "title": "short line",
  "file": "relative/path",
  "line": 42,
  "evidence": "raw detector output",
  "detector": "name",
  "detected_at": "ISO-8601",
  "fingerprint": "stable across runs"
}
```

`fingerprint` is `detector:file:line:title`. It stays the same between
runs for the same underlying issue.

## Rules

1. Read-only. No file inside the scanned project is written. Ever.
2. Evidence or silence. Every finding carries file, line, and detector output.
3. One proposal per finding. Concrete action, not "improve security".
4. Deterministic proposals. Same findings -> same proposals. No LLM in the default path.
5. Missing tool, missing detector. If a tool is absent, its detector is skipped, not faked.

## License

MIT. See LICENSE.
