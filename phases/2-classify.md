# Phase 2 - Classify

Purpose: sanity-check the findings, drop obvious noise, confirm sort order.

## Steps

1. Read run/findings.json.

2. Check the sort order.
   Findings are already sorted by severity (critical first), then by
   category, file, line. Do not re-sort unless you have a specific reason
   and say so.

3. Drop obvious noise - only if the evidence clearly shows it:
   - secrets finding inside a file whose name contains "test" or "example",
     where the value matches a well-known placeholder pattern.
   - todo-fixme finding inside docs/ or a .md file, where the marker
     is part of a template rather than a live work item.

   Anything dropped must be recorded in run/scan.log under a
   "## dropped by phase 2" section, with the finding id and the reason.

4. Do not invent findings. If findings.json is empty, that is the
   answer. Do not scan again with looser rules.

5. Do not merge findings with different fingerprints. Even if two look
   similar, if their fingerprints differ they are different issues.

## Output

Nothing new is written. The classified list is used as-is by phase 3.

## Announce

One line: Классификация: N после отсева (было M). - then phase 3.
If nothing was dropped, just: Классификация: N находок.
