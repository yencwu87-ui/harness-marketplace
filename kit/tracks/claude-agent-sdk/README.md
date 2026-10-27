# Track: Claude Agent SDK (Python)

The Claude Code harness, driven from your own code: CI jobs, scheduled runs, or inside a product.

```bash
make setup TRACK=claude-agent-sdk
export ANTHROPIC_API_KEY=...
make run TRACK=claude-agent-sdk          # works on the next failing item in your repo
.venv/claude-agent-sdk/bin/python tracks/claude-agent-sdk/agent.py --ask "hello"
```

`agent.py` shows: one item per run; model and effort set once; a small tool surface (`Read`, `Edit`,
`Write`, `Bash`, `Agent`, plus `mcp__kit__search_code`, a content search that never opens secret files, and never follows a symlink to a secret or out of
the repo;
the built-in `Grep` and `Glob` are not offered, because their globs and roots can reach secret files);
a PreToolUse hook that refuses secret paths, recursive shell searches, destructive commands and writes
outside the repo; the shell sandbox; a Haiku `explore` subagent with the same restricted tools; turn and
budget limits (`KIT_MAX_TURNS`, `KIT_MAX_BUDGET_USD`); usage appended to `progress/usage.log`.

`--ask` is a one-shot answer with no tools (for the prompt test suites). `--repo . --task "..."` runs the
production work agent, with the same tools, hook and instructions, on a given task; the live red team's
`claude-agent-sdk` preset uses it, so its attacks reach the agent you ship.
It loads your repo's `CLAUDE.md` and `.claude/` too, so install the Claude Code files as well.
The SDK runs the Claude Code engine underneath; if it can't find it, `npm install -g @anthropic-ai/claude-code`.
A TypeScript SDK exists too (`@anthropic-ai/claude-agent-sdk`).
