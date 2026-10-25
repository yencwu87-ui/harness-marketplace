# Track: Claude Agent SDK (Python)

The Claude Code harness, driven from your own code: CI jobs, scheduled runs, or inside a product.

```bash
make setup TRACK=claude-agent-sdk
export ANTHROPIC_API_KEY=...
make run TRACK=claude-agent-sdk          # works on the next failing item in your repo
.venv/claude-agent-sdk/bin/python tracks/claude-agent-sdk/agent.py --ask "hello"
```

`agent.py` shows: one item per run; model and effort set once; a PreToolUse hook that refuses
secret paths; the shell sandbox; a Haiku `explore` subagent; turn and budget limits
(`KIT_MAX_TURNS`, `KIT_MAX_BUDGET_USD`); usage appended to `progress/usage.log`.
It loads your repo's `CLAUDE.md` and `.claude/` too, so install the Claude Code files as well.
The SDK runs the Claude Code engine underneath; if it can't find it, `npm install -g @anthropic-ai/claude-code`.
A TypeScript SDK exists too (`@anthropic-ai/claude-agent-sdk`).
