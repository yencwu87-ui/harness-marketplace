# harness-audit

`/harness-audit:audit` scores your repository's agent harness out of 100 across seven areas, with evidence (`file:line`) for every pass and a one-line fix for every gap:

1. Instructions · 2. State and continuity · 3. Verification · 4. Scope and stopping · 5. Safety guardrails · 6. Evals and red teaming · 7. Cost and context

Also runs on its own, with no dependencies: `python3 skills/audit/scripts/audit.py /path/to/repo [--md|--json] [--strict] [--min 70]`.
Areas 1–4 follow WalkingLabs' Learn Harness Engineering course (MIT). Areas 5–7 are what production teams add. A pass means the piece exists in files, not that it works.
