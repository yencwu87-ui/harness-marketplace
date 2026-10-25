# Track: Microsoft Agent Framework (Python; .NET also available)

Model-neutral. Pick the provider with `KIT_PROVIDER` = `anthropic` (default), `openai`, `foundry`, `ollama`.

```bash
make setup TRACK=microsoft-agent-framework     # uses --pre: the Anthropic connector is pre-release
export ANTHROPIC_API_KEY=...                   # or OPENAI_API_KEY, or `az login` + KIT_FOUNDRY_ENDPOINT
make run TRACK=microsoft-agent-framework
```

`harness_agent.py` uses `create_harness_agent`, which wires in a todo list, plan/execute mode,
file memory, context compaction, skills (it reads `.claude/skills` if present) and tool approval.
`record_result` is marked `approval_mode="always_require"`, so a human approves every change to the
work list. Next steps: workflows (`WorkflowBuilder`, sequential/concurrent/handoff orchestrations),
MCP tools (`MCPStdioTool`), DevUI for local debugging, and `evaluate_agent` for built-in evals.
.NET: `dotnet add package Microsoft.Agents.AI`.
