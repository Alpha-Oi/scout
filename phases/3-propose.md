# Phase 3 - Propose

Purpose: attach one concrete proposal to every finding.

## Run

    python tools/propose.py <run_dir>

## What it does

Reads run/findings.json, writes run/proposals.json:

    [
      {
        "id": "sha1:abc123",
        "proposal": "one concrete action",
        "risk": "low|medium|high",
        "effort": "S|M|L"
      }
    ]

## Rules the proposals must respect

1. One action. Not "improve security" - "update pypdf2 to 3.9.0".
2. Deterministic. Same finding -> same proposal. The default path never
   calls an LLM. If a rule cannot produce a concrete action, the fallback
   is "Требуется ручная оценка" with risk: low, effort: M.
3. No promises about correctness. "Update X to Y and run tests" is fine.
   "This will fix everything" is not.

## Routing table

| Detector | Proposal shape |
|---|---|
| pip-audit | Update pkg from v to fix, check changelog, run tests |
| secrets | Move to .env, add .gitignore, rotate the key |
| pytest-failed | pytest --lf -v, inspect traceback, fix code or test |
| todo-fixme | Resolve the marker: implement or delete |
| other | Manual review needed |

## Announce

One line: Предложения: N сформулировано. - then phase 4.
