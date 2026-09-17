# Phase 4 - Render

Purpose: build the dashboard and open it for the user.

## Steps

1. Build state.js.

    python tools/render.py <run_dir>

   This reads findings.json and proposals.json and writes
   report_root/state.js.

2. Copy the dashboard template (only if it is not already there).

    copy tools/dashboard.html report_root/dashboard.html

   On Unix: cp. On any platform the Python copy works too.

3. Inline the snapshot.

    python tools/sync.py <report_root>

   This writes the current state between the /*STATE-BEGIN*/ and
   /*STATE-END*/ markers inside dashboard.html. The page then shows
   data even when opened as a plain file, without a server.

4. Open the dashboard.

   - Windows: Start-Process report_root\dashboard.html
   - macOS: open report_root/dashboard.html
   - Linux: xdg-open report_root/dashboard.html

5. Final chat message. One short paragraph:

   - Path to the dashboard.
   - Counts: critical C, high H, medium M, low L.
   - Top finding by severity, if any.
   - Reminder: Scout reports; fixing is a separate step.

## Announce

One line: Дашборд готов: <path>. Критично C, высоко H, средне M, низко L.

Nothing more.
