---
name: scout
description: >
  Scan a project folder for bugs, vulnerabilities, unfinished work, and
  improvement opportunities. Render findings to a dashboard and propose
  one concrete action per finding. Read-only: never edits the project.
  Use on /scout <path>, "просканируй проект", "что тут можно улучшить",
  "найди баги", "проверь проект на уязвимости".
argument-hint: "[full|quick] <путь к проекту>"
---

# Scout

Scout examines a project and reports. It never edits anything.

## What it does

1. Verifies itself (phase 0).
2. Runs detectors on the project - external tools and small scripts (phase 1).
3. Classifies findings into bug / vuln / incomplete / improvement (phase 2).
4. Formulates one concrete proposal per finding (phase 3).
5. Renders a dashboard in the report directory and opens it (phase 4).

## What it never does

- Edits any file inside the scanned project.
- Runs git commit, git push, or any write into the project.
- Invents findings. No detector - no finding.
- Fixes anything. Fixing is a different skill.

## How to read this skill

This file is the orchestrator. The rules for each phase live in phases/
and are read at the moment the phase starts, not before. One file at a
time. That is what keeps the working context small.

| Phase | Read | Produces |
|---|---|---|
| 0 Preflight | phases/0-preflight.md | report folder created, tools verified |
| 1 Scan | phases/1-scan.md | run/findings.json, run/scan.log |
| 2 Classify | phases/2-classify.md | findings reviewed and sorted |
| 3 Propose | phases/3-propose.md | run/proposals.json |
| 4 Render | phases/4-render.md | state.js, dashboard.html opened |

## Runtime tools

All tools live in tools/ and are Python scripts. They do not depend on
the host platform and run identically on Windows, macOS and Linux.

| Tool | Role |
|---|---|
| tools/scan.py | runs detectors, writes findings.json |
| tools/propose.py | writes proposals.json (deterministic rules) |
| tools/render.py | builds state.js from findings + proposals |
| tools/sync.py | inlines state.js into dashboard.html |
| tools/dashboard.html | the view; self-contained, opens as a file |

## Layout

report_root/
  YYYY-MM-DD-slug/
    findings.json
    proposals.json
    scan.log
  state.js
  dashboard.html

report_root is chosen by the user (default ./.scout). Scout never
writes inside the scanned project.

## Rules

1. Read-only. No file inside the scanned project is written. Ever.
2. Evidence or silence. Every finding carries file, line, and detector output.
3. One proposal per finding. Concrete action, not "improve security".
4. Deterministic proposals. Same findings -> same proposals. No LLM in the default path.
5. Missing tool, missing detector. If a tool is absent, its detector is skipped, not faked.
