# Track: OpenAI Agents SDK (Python; TypeScript SDK also available)

Supported (full). Model-neutral through any OpenAI-compatible Chat Completions endpoint.

```bash
make setup TRACK=openai-agents-sdk
export OPENAI_API_KEY=...                     # and OPENAI_BASE_URL for a gateway or another provider
make run TRACK=openai-agents-sdk
```

`agent.py` runs an `Agent` with `@function_tool` tools through `Runner.run`. `RunHooks.on_tool_start`
(`TraceTools`) writes every tool call to `$HARNESS_TRACE` for the live red team. The SDK's own trace
export to OpenAI is off unless `KIT_OPENAI_TRACING=1`, so the only outbound calls are the model calls you
point it at. Model: `KIT_MODEL_ID`. Next steps: handoffs between agents, guardrails, and sessions for memory.
