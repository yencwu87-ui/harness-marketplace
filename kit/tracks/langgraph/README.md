# Track: LangGraph (Python)

Supported (full). Claude through the Anthropic API by default, or any OpenAI-compatible endpoint.

```bash
make setup TRACK=langgraph
export ANTHROPIC_API_KEY=...                  # or KIT_PROVIDER=openai + OPENAI_API_KEY (and pip install langchain-openai)
make run TRACK=langgraph
```

`agent.py` builds the agent with `langchain.agents.create_agent` (the LangGraph agent loop that replaced `create_react_agent` in LangGraph 1.0) and a LangGraph checkpointer, so a session
keeps its place under a `thread_id` (`KIT_THREAD`). Swap `InMemorySaver` for a SQLite or Postgres saver to
resume across processes. A LangChain callback (`TraceTools.on_tool_start`) writes every tool call to
`$HARNESS_TRACE` for the live red team. Point model calls at your gateway with `ANTHROPIC_BASE_URL` or
`OPENAI_BASE_URL`. Next steps: human-in-the-loop with `interrupt_before`, and LangGraph Studio for debugging.
