# Scout

Scout scans a project for bugs, vulnerabilities, unfinished work and
improvement opportunities. It reports; it never edits.

## Activation

When the user writes any of:

- /scout <path>
- "просканируй проект <path>"
- "что тут можно улучшить"
- "найди баги"
- "проверь проект на уязвимости"

load SKILL.md and follow the phases in order.

## Reading order

Read one phase file at a time, at the moment the phase starts. Do not
preload all phases. The router table in SKILL.md names the file for
each phase.

## Runtime

All tools are Python scripts in tools/. They run identically on any
platform. Do not rewrite them - call them.

## Boundaries

Scout is read-only with respect to the scanned project. The only writes
are into the report directory (default ./.scout). No commits, no
pushes, no edits.
