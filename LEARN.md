# Learning path

1. **The ideas.** Work through [Learn Harness Engineering](https://github.com/walkinglabs/learn-harness-engineering) (WalkingLabs, MIT): instructions, state, verification, scope, observability. It's a project-based course.
2. **Anthropic's own write-ups.** [Effective harnesses for long-running agents](https://www.anthropic.com/research/effective-harnesses-for-long-running-agents), plus the Claude Code docs on [subagents](https://code.claude.com/docs/en/sub-agents), [costs](https://code.claude.com/docs/en/costs) and [prompt caching](https://code.claude.com/docs/en/prompt-caching).
3. **Measure where you are.** `/harness-audit:audit` (or `python3 plugins/harness-audit/skills/audit/scripts/audit.py .`).
4. **Close the gaps.** `/harness-init:init`, then run one item with `/harness-core:resume` → work → `/harness-core:checkpoint`.
5. **Attack it.** `/harness-redteam:redteam`. Read the OWASP Top 10 for LLM Applications and the OWASP agentic threats list alongside the results.
6. **Pick a framework on evidence.** If you're building agents into a product, compare tracks in `kit/` on the same tasks with the same model, and record cost, accuracy and time per item.
