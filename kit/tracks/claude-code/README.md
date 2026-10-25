# Track: Claude Code

Config-only. `make install TRACK=claude-code` copies `CLAUDE.md` and `.claude/` into your repo
(existing files are left alone; merge by hand and never remove a deny rule).

| File | What it does |
|---|---|
| `CLAUDE.md` | Short rules loaded every session (keep under 200 lines) |
| `.claude/settings.json` | Model, deny rules for secrets and destructive git, shell sandbox, 1-hour subagent cache, test-output filter hook |
| `.claude/agents/explore.md` | Overrides built-in Explore with read-only **Haiku**; returns `file:line` evidence |
| `.claude/agents/verifier.md` | Read-only **Sonnet** checker; returns VERIFIED / INCORRECT / UNRESOLVED |
| `.claude/hooks/filter-test-output.sh` | Plain `pytest` / `npm test` / `go test` runs show only failures (needs `jq`) |
| `.claude/skills/resume`, `checkpoint` | Start-of-session and end-of-session routines |

Start a session:
```
claude
/model opus
/effort medium
> Run the resume skill, then work on the next item. Stop when done_when is met or after two failed attempts, then run checkpoint.
```
Afterwards check `/context` and `/usage` (look at the `Prompt cache (main)` line).
The `sandbox` setting needs OS support (macOS Seatbelt, Linux bubblewrap); if it isn't available,
use the locked-down Docker environment.
