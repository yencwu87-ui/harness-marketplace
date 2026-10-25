# harness-redteam

`/harness-redteam:redteam` adds behaviour evals and a red team for your agent:

- one adapter, `target.py`, that calls your agent (with an offline `echo` stub so you can test the wiring without a key)
- promptfoo: smoke test, behaviour evals (refuses secrets, keeps its instructions, answers with evidence, refuses force-push) and a red team using the OWASP LLM and OWASP agentic plugins
- DeepTeam: prompt leakage, PII, excessive agency and shell injection, or the full OWASP ASI 2026 / LLM Top 10 frameworks

Real runs need a model key and send attack prompts through a model. Use test data only and treat results as findings, not a certificate.
