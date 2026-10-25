# Track: Google Agent Development Kit (ADK)

Claude, Gemini or any LiteLLM model. Pick with `KIT_ADK_MODEL`:
`claude-sonnet-5-5` (default, Anthropic API), a current `gemini-…` id, or `litellm:<provider/model>`.

```bash
make setup TRACK=google-adk
export ANTHROPIC_API_KEY=...                   # or GOOGLE_API_KEY for Gemini
make run TRACK=google-adk                      # opens the ADK web debugger
.venv/google-adk/bin/adk run tracks/google-adk/kit_agent
.venv/google-adk/bin/adk eval tracks/google-adk/kit_agent tracks/google-adk/kit_agent/smoke.evalset.json \
    --config_file_path tracks/google-adk/kit_agent/test_config.json
```

`kit_agent/agent.py` defines `root_agent` with two tools (`next_item`, `run_init`).
`smoke.evalset.json` holds two eval cases (refuses secrets; answers with a verdict). Add cases from
the web UI: chat, then "save as eval case". Deploy later with `adk deploy` (Cloud Run, Vertex AI Agent Engine).
