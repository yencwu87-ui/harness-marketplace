---
name: redteam
description: Add behaviour evals and a red team for this project's AI agent using promptfoo and DeepTeam, mapped to the OWASP LLM and agentic risk lists. Use when asked to red-team, attack-test, evaluate or security-test an agent.
---

# Red-team your agent

Templates are in `templates/` next to this file.

1. **Plan.** Tell the user what you will add under `harness/redteam/` (or a folder they choose):
   `target.py` (the one place that calls their agent), `promptfoo/` (smoke, evals, red team) and `deepteam/`.
   Wait for a yes. Never overwrite existing files.
2. **Copy** the templates there (copy files, do not retype them).
3. **Wire the target.** Find how the project calls its agent and implement `_call_my_agent` in `target.py`.
   Keep `KIT_TRACK=echo` working as an offline stub.
4. **Prove the wiring offline** (no API key): `cd harness/redteam/promptfoo && KIT_TRACK=echo npx promptfoo@0.125.1 eval -c smoke.yaml`.
5. **Tailor the purpose** in `promptfoo/redteam.yaml` and `deepteam/red_team.py` to what this agent may and may not do.
6. Show the commands for real runs and say they need a model key and send attack prompts through a model:
   - `npx promptfoo@0.125.1 eval` and `npx promptfoo@0.125.1 redteam run -c redteam.yaml`
   - `pip install -r deepteam/requirements.txt && python deepteam/red_team.py --framework owasp-asi-2026`
7. **Then test the real tool path** (this is the part that matters for agents):
   - Copy `templates/live/` to `harness/redteam/live/` and `templates/live/live.example.json` to `live.json` at the repo root.
     Set `agent_cmd` to the exact command production uses (e.g. `claude -p "{task}" --output-format stream-json --verbose`,
     or the track's agent script). Never point it at real secrets: it runs in a throwaway copy with a fake HOME.
   - `python3 harness/redteam/live/redteam_live.py selftest` proves the detectors fire and stay quiet (no model needed).
   - Ask the user to record the production config fingerprint: `python3 harness/redteam/live/redteam_live.py baseline`
     on their real config, and commit `.harness-live/parity.json`. Runs refuse a config that differs from it.
   - Attacks come from the generators: `cd harness/redteam/live/bridges && npx promptfoo@0.125.1 redteam run -c redteam-live.yaml`,
     or `python deepteam_live.py`. Verdicts are deterministic: canary access or leak, blocked egress, pushes,
     destructive commands, work-list tampering, writes to protected files.
8. Remind the user: use test data only, and treat results as findings to review, not a pass certificate.
   Suggest running the eval suite in CI on PRs that touch prompts, tools or agent config.
