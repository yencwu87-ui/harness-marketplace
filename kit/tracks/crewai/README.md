# Track: CrewAI (Python)

Supported (full). Claude through the Anthropic API by default. CrewAI's `LLM` also reaches OpenAI,
Bedrock, Gemini, Azure and local models.

```bash
make setup TRACK=crewai
export ANTHROPIC_API_KEY=...                  # KIT_MODEL takes CrewAI's "<provider>/<model>" form
make run TRACK=crewai
```

`agent.py` runs a one-agent `Crew` with a `Task` per request. A before-tool-call hook (`trace_tool`) writes
every tool call to `$HARNESS_TRACE` for the live red team. CrewAI's anonymous telemetry is switched off here
unless `KIT_CREWAI_TELEMETRY=1`. Point model calls at your gateway with `KIT_BASE_URL` (or
`ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`). Next steps: more agents and tasks in one crew, and Flows for
event-driven pipelines.
