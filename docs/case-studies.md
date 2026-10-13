# Кейсы: Scout на самом себе

Перенесено из прежнего README как есть (на английском).

## Самосканирование

Scout runs its own detectors on itself.

```
scout: 59 findings -> scout-reports/2026-09-19-scout-13
  critical 0
  high     0
  medium   15
  low      44
```

No critical or high findings. Ruff and mypy both clean. Max complexity in `scan.py`: 13 (was 32 before refactor).

---

## CI caught what local scan missed

The self-scan runs in GitHub Actions with a clean environment — no caches,
fresh detector versions. This caught a bug that local scans never showed.

`.pyscn/reports/analyze_*.json` — pyscn's own output from a previous run —
was scanned by `detect-secrets`, which flagged 36 false positives. Locally
`.pyscn/` was recreated on each run and never persisted; in CI it survived
between steps.

Fixed in two commits:

- `ad5508f` — `.pyscn/` in `EXCLUDE_DIRS` (file iterator)
- `5fc0098` — `.pyscn/` in `SKIP_RE` inside `detect_detect_secrets`
  (that detector runs its own walk via the external tool)

Only the second fix worked — `detect-secrets` has its own file traversal
separate from the shared iterator.

---
