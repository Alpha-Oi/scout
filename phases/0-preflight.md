# Phase 0 - Preflight

Purpose: verify Scout is intact, verify the target, create the run folder.

## Steps

1. Verify Scout.
   Run: python scripts/verify-skill.py
   It must print "scout check: OK".
   If it fails - stop. Do not scan a project with a broken scanner.

2. Verify the target.
   - The path exists and is a directory.
   - It is a git repository (.git/ directory or .git file). If not,
     the scan is still allowed, but note in the final chat message that
     git-based detectors were skipped.

3. Resolve the report root.
   - If the user gave --out, use it.
   - Otherwise ./.scout relative to the current working directory.
   - Never place the report root inside the scanned project.

4. Create the run folder.
   - report_root/YYYY-MM-DD-slug/ where slug is the target folder name,
     lowercased, non-alphanumerics replaced by dash.
   - If it exists - append -2, -3, etc.

5. Copy the dashboard.
   - tools/dashboard.html -> report_root/dashboard.html,
     only if not already present there.

## Announce

One line to chat: Scout готов. Сканирую <path>.

No further narration until phase 4.
