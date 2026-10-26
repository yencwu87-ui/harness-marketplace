# harness-audit

`/harness-audit:audit` scores your repository's agent harness out of 100 across seven areas, with evidence (`file:line`) for every pass and a one-line fix for every gap:

1. Instructions · 2. State and continuity · 3. Verification · 4. Scope and stopping · 5. Safety guardrails · 6. Evals and red teaming · 7. Cost and context

Also runs on its own, with no dependencies: `python3 skills/audit/scripts/audit.py /path/to/repo [--md|--json] [--strict] [--min 70]`.
Areas 1–4 follow WalkingLabs' Learn Harness Engineering course (MIT). Areas 5–7 are what production teams add. A pass means the piece exists in files, not that it works.

## Frameworks other than Claude Code (1.4.1)

The audit detects the agent framework from the repo's own files. It reads Python imports with `ast`, plus requirements files and `package.json`. Nothing in the repo is imported or run, and test files are ignored. Guard checks G1–G3 then look for the equivalent evidence in that framework, so the same guard quality earns the same points on every supported track:

- **G1 (3):** an explicit tool list, with every broad tool in it gated by the framework's own approval or deny step. "Broad" means shell or code execution, writing anywhere, web fetch, or computer use.
- **G2 (3):** no tool can read files, run commands, fetch URLs or use a computer; or a gate refuses secret paths (`.env`, `.pem`, `.key`, `.ssh`, `.aws`).
- **G3 (2):** no tool can run commands, write anywhere or use a computer; or a person approves those calls; or a gate refuses `git push`, `reset --hard` and `rm -rf`.

Claude Code is still judged on `.claude/settings.json`, exactly as before. When a repo has several agent surfaces, a check passes only when every surface passes it. For assess-only frameworks the audit can't parse tool lists yet. What `docs/IMPACT.md` states (sections "Tools", "Secrets" and "Destructive actions") is marked **DECLARED** and earns half the check's weight. Derived evidence always takes precedence over declared evidence.
