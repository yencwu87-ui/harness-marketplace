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
