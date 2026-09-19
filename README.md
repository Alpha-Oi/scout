# Scout

Read-only project scanner with a dashboard. Finds bugs, vulnerabilities,
unfinished work and improvement opportunities. Proposes one concrete action
per finding. Never edits the scanned project.

Works on Windows, macOS and Linux. Runs as a skill in Claude Code, Cursor
and Codex, or as a plain CLI.

## What it looks like

The dashboard is a single self-contained HTML file. Opens as a file, from
a webserver, from a panel — no dependencies.

```
[report_root]/
├── dashboard.html      the view
├── state.js            the current run state
├── diff.json           comparison with the previous run (if any)
└── 2026-09-19-project/
    ├── findings.json
    ├── proposals.json
    └── scan.log
```

## Detectors

| Detector | Category | What it finds |
|---|---|---|
| `pytest-failed` | bug | Failing tests |
| `pip-audit` | vuln | Known CVEs in dependencies |
| `pip-outdated` | improvement | Outdated deps from requirements.txt |
| `bandit` | vuln | eval, subprocess(shell=True), weak crypto |
| `ruff` | bug / improvement | Undefined names, unused imports, style |
| `mypy` | bug | Type errors — None, attributes, arguments |
| `vulture` | improvement | Dead code |
| `radon` | improvement | Cyclomatic complexity |
| `interrogate` | improvement | Missing docstrings |
| `pyscn` | improvement | Code clones |
| `semgrep` | vuln | SAST with curated rules |
| `detect-secrets` | vuln | Entropy-based secret detection |
| `todo-fixme` | incomplete | TODO / FIXME markers |
| `secrets` | vuln | Regex-based keys and tokens |

Missing tools are skipped, not faked. If `bandit` is not installed,
the detector logs `not installed — skip` and the scan continues.

## Install

```sh
git clone https://github.com/Alpha-Oi/scout.git
cd scout
python scripts/verify-skill.py
```

Requirements: Python 3.11+. Optional tools, install what you need:

```sh
python -m pip install pip-audit mypy ruff bandit vulture radon \
                       interrogate detect-secrets semgrep
```

`pyscn` runs through `uv` automatically if installed.

## Run

### CLI

```sh
# Scan
python tools/scan.py <path-to-project> --out ./reports

# Optional: fast pass (skips pytest and pip-audit)
python tools/scan.py <path> --out ./reports --quick

# Propose
python tools/propose.py ./reports/<run-dir>

# Optional: with LLM
python tools/propose.py ./reports/<run-dir> --llm

# Diff against previous run
python tools/diff.py ./reports/<previous> ./reports/<current>

# Render
python tools/render.py ./reports/<run-dir>
python tools/sync.py ./reports
```

Open `./reports/dashboard.html`.

### In Claude Code / Cursor / Codex

```
/scout C:\path	o\project
```

The skill walks the phases: preflight → scan → classify → propose → render.

## Flags

| Flag | Effect |
|---|---|
| `--out <dir>` | Report root (default `./.scout`) |
| `--quick` | Skip slow detectors (pytest, pip-audit) |
| `--llm` | Use LLM for proposals |
| `--llm-max N` | LLM request budget (default 20) |

## Configuration — `.scoutrc`

Drop a `.scoutrc` file in the project root:

```json
{
  "skip_detectors": ["pyscn", "semgrep"],
  "severity_rules": {
    "todo-fixme": "low",
    "interrogate": "low"
  },
  "max_findings_per_detector": {
    "pip-outdated": 20,
    "ruff": 200
  }
}
```

See `.scoutrc.example` for the full set of options.

## Dashboard

Three views:

- **По находкам** — flat list, sorted by severity.
- **По кодам** — grouped by rule code. One card per distinct issue type,
  with a `×N` badge and every `file:line` inside. Collapses 100 cards into
  10–20 actions.
- **Diff** — compared to the previous run. New findings get a `NEW` badge,
  disappeared ones appear under «Исчезли» with a strikethrough.

## LLM proposals (optional)

Off by default. Enable with `--llm`. Provider chosen automatically:

- `ANTHROPIC_API_KEY` → Claude
- `OPENAI_API_KEY` → GPT
- Ollama on `127.0.0.1:11434` → local model

```sh
# Claude
export ANTHROPIC_API_KEY=sk-ant-...

# Ollama, local
ollama pull qwen2.5:7b
ollama serve

# Then
python tools/propose.py ./reports/<run> --llm --llm-max 20
```

Responses cached in `.scout-llm-cache.json`, keyed by `fingerprint`.
Same finding won't be asked twice.

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

`fingerprint` = `detector:file:line:title`. Same underlying issue keeps the
same fingerprint between runs — that is what makes `diff` possible.

## Rules

1. **Read-only.** No file in the scanned project is written.
2. **Evidence or silence.** Every finding carries file, line, and detector output.
3. **One proposal per finding.** Concrete action, not "improve security".
4. **Deterministic by default.** Same findings → same proposals. LLM is opt-in.
5. **Missing tool, missing detector.** Nothing is faked.

## Layout

```
scout/
├── SKILL.md              the skill (phases, rules)
├── phases/               per-phase rules, read one at a time
├── tools/                runtime — Python scripts + dashboard
├── scripts/              verify-skill.py, build-adapters.py
├── AGENTS.md             adapter for Codex
├── CLAUDE.md             adapter for Claude Code
├── .cursor/rules/        adapter for Cursor
├── .scoutrc.example      config template
└── .github/workflows/    CI: verify-skill on every push
```

## License

MIT. See LICENSE.
