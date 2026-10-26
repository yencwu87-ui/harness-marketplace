# Track: AWS Strands Agents (Python; TypeScript SDK also available)

Supported (full). Claude through the Anthropic API by default, or Amazon Bedrock with your AWS credentials.

```bash
make setup TRACK=strands-agents
export ANTHROPIC_API_KEY=...                  # or KIT_PROVIDER=bedrock + AWS credentials + a Bedrock KIT_MODEL_ID
make run TRACK=strands-agents
```

`agent.py` builds a Strands `Agent` with `@tool` tools. A hook provider (`TraceTools`) on
`BeforeToolCallEvent` writes every tool call to `$HARNESS_TRACE` for the live red team. Point model calls at
your gateway with `ANTHROPIC_BASE_URL`. Next steps: session managers for resume, and the multi-agent
patterns (graph, swarm).
