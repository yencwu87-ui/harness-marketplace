---
name: audit
description: Score this repository's agent harness across 7 areas and list exactly what to fix. Use when asked to audit, review, score or check a harness, or before setting one up.
---

# Harness audit

1. Run the audit script that sits next to this file, against the project root (read-only, no dependencies):
   ```bash
   python3 "<this skill's base directory>/scripts/audit.py" . --md
   ```
2. Show the user the score and the table. Then, in plain words, list the **critical** gaps first (marked ❌ with weight 3), then the rest, grouped by area.
3. For each gap, say the smallest fix. If the `harness-init` plugin is installed, say which gaps `/harness-init:init` would close.
4. Do not change any files during an audit. Offer to fix; wait for a yes.

Notes for the user:
- A pass means the harness piece exists in files, not that it works. The proof is running the checks.
- `--json` gives machine-readable output for CI; `--strict` exits 1 when any critical check fails; `--min 70` fails below a score.
- Areas 1–4 (instructions, state, verification, scope) follow WalkingLabs' Learn Harness Engineering course. Areas 5–7 (safety guardrails, evals and red team, cost and context) are what production teams add on top.
- Other frameworks: the audit detects LangGraph, OpenAI Agents SDK, CrewAI, Strands, Google ADK, Microsoft Agent Framework and the Claude Agent SDK from the repo's imports (read, never run) and checks their own guard mechanisms for G1–G3. For assess-only frameworks, what `docs/IMPACT.md` states counts as DECLARED, at half weight.
