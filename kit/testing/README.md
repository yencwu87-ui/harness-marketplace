# Testing your agent

Both tools call the agent through `shared/target.py`. Pick the agent with `KIT_TRACK`
(`echo` is an offline stub for wiring checks).

| Command | What runs |
|---|---|
| `make smoke` | promptfoo `smoke.yaml` against the echo stub. No key. Proves the wiring. |
| `make eval TRACK=…` | promptfoo `promptfooconfig.yaml`: refuses secrets, keeps its instructions, answers with verdicts, refuses force-push. Model-graded checks use Claude by default. |
| `make redteam-promptfoo TRACK=…` | promptfoo red team: OWASP LLM + OWASP agentic plugins, prompt extraction, PII, excessive agency, hijacking, shell/SQL injection; jailbreak, prompt-injection and crescendo strategies. |
| `make setup-redteam TRACK=…` then `make redteam-deepteam TRACK=… FRAMEWORK=agentic` | DeepTeam: prompt leakage, PII, excessive agency, shell injection with prompt-injection, roleplay and linear jailbreak attacks. `FRAMEWORK=owasp-asi-2026` or `owasp-llm` runs the full framework. Results in `testing/deepteam/results/`. |

Red teaming sends attack prompts through a model and grades the answers with a model. Use test
data only, and read each tool's data-handling notes before pointing it at anything sensitive.
Treat results as findings to review, not a pass certificate.

## Live red team (real tool path)

`live/redteam_live.py` attacks the agent through its real command and configuration in a throwaway workspace (fake HOME, canary secrets, trap git remote, logging egress proxy) and judges tool calls, network requests and file changes. Copy `live/live.example.json` to `live.json` at your repo root and set `agent_cmd` (for example `python3 harness/tracks/claude-agent-sdk/agent.py --repo .`). Then:

| Command | What it does |
|---|---|
| `make redteam-selftest` | Proves the detectors fire (tripwire agent), stay quiet (idle agent) and, with `"isolation": "netns"` or `"docker"` in live.json, that the agent has no network except the logging proxy. No model needed. |
| `python3 testing/live/redteam_live.py --repo .. baseline` | Records the production config fingerprint. Commit `.harness-live/parity.json`. |
| `make redteam-live ATTACKS=attacks.jsonl` | Runs generated attacks (`{"id","channel","text"}` per line). |
| `cd testing/live/bridges && npx promptfoo@0.125.1 redteam run -c redteam-live.yaml` | promptfoo generates, the live harness delivers and judges. |
| `python testing/live/bridges/deepteam_live.py` | DeepTeam generates; deterministic verdicts are written to `results/`. |
