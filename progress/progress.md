# Progress

**Updated:** 27 Oct 2026  **Item:** 1.4.4, Codex round-3 fix round (coordinator brief, not a work-list item)  **Status:** passed locally, awaiting Codex round 4 and owner review

## What changed
- plugins/harness-audit/skills/audit/scripts/audit.py (1.4.4): credit only canonical guard forms (CANONICAL_FORMS, --canonical-forms), fail-closed reach, unreadable MCP maps UNRESOLVED, one rule standard for SDK and settings, sandbox credit only without escapes, every read contained in the root
- kit/shared/kit_guard.py (pinned by sha256) and its copy in kit/tracks/claude-agent-sdk; the SDK starter hook leads with canonical refusals
- init template and Claude Code track settings: allowUnsandboxedCommands false
- tests/test_audit_r3.py, tests/test_audit_nearmiss.py (round-3 families), tests/fixtures/codex_r3/

## Verdicts
- R3-01 to R3-07 evidence-to-close tests: VERIFIED (logs/1.4.4/red_r3_findings.log red on 1.4.3; green in the full run)
- Independent review's 13 bypasses: VERIFIED closed (logs/1.4.4/red_independent_review.log red, then green)
- Fairness matrix unchanged a=8 b=0 c=2 on 8 tracks, kit starters 8/8: VERIFIED (logs/1.4.4/fairness_and_fixtures_after.txt)
- Tests that need a TCP bind (12): UNRESOLVED in this session (the sandbox refuses bind; the same 12 fail on 1.4.3 here)
- Installed-framework smokes, live model runs: UNRESOLVED (frameworks not installed here; no API keys, as M-003)
- This repo's own .claude/settings.json lacks allowUnsandboxedCommands false, so its self-audit G2 is UNRESOLVED (93/100): owner decision

## Usage
- Wall-clock: 27 Oct 2026 19:15 to about 20:25 +08 (one session)
- Tokens: not available to this headless session

## Blocker
none

## Next action
Coordinator verifies the Codex package and starts round 4.

---

**Updated:** 27 Oct 2026  **Item:** 1.4.3, Codex round-2 fix round (coordinator brief, not a work-list item)  **Status:** passed locally, awaiting Codex round 3 and owner review

## What changed
- plugins/harness-audit/skills/audit/scripts/audit.py (1.4.3): refusal analysis by OR-branch with enclosing conditions, scope-aware Claude Code rules, SDK MCP server binding, reach that never drops a capability, no secret files or outward symlinks read
- kit/tracks/claude-agent-sdk/agent.py: search_code and the hook check symlink targets
- tests/test_audit_r2.py, tests/test_audit_nearmiss.py, tests/test_live_safety.py (R2-06), tests/fixtures/codex_r2/, tests/fixtures/audit_1_4_1/

## Verdicts
- R2-01 to R2-06 evidence-to-close tests: VERIFIED (logs/r143/red_r2_findings.log red on 1.4.2; green in the full run)
- Shallow-clone CI defect: VERIFIED (logs/r143/red_ci_shallow_clone.log, logs/r143/green_ci_shallow_clone.log)
- Fairness matrix unchanged a=8 b=0 c=2 on 8 tracks: VERIFIED (logs/r143/fairness_matrix_after.txt)
- Installed-framework smokes, live model runs: UNRESOLVED (frameworks not installed here; no API keys, as M-003)

## Usage
- Wall-clock: 27 Oct 2026 18:30 to about 19:00 +08 (one session)
- Tokens: not available to this headless session

## Blocker
none

## Next action
Coordinator verifies the Codex package and starts round 3.

---

**Updated:** 26 Oct 2026  **Item:** 1.4.0 tracks (owner request, not yet a work-list item)  **Status:** passed locally, awaiting owner review

## What changed
- kit/tracks/{langgraph,openai-agents-sdk,crewai,strands-agents}: starters, pinned requirements, trace hooks, READMEs
- kit/tracks/{llamaindex,pydantic-ai,smolagents,haystack,dspy,agno,mastra,vercel-ai-sdk}: assess-only spec + README
- kit/tracks/*/harness_track.json and kit/tracks/TRACK_SPEC.md: the track spec
- tools/redteam_live/redteam_live.py (+ synced copies): "track" presets in live.json
- tests/test_tracks.py, tests/llm_stub.py: spec checks and offline smoke tests

## Verdicts
- Spec checks: VERIFIED (python3 -m unittest discover -s tests: OK, smoke tests skipped without frameworks)
- Smoke test per new full track: VERIFIED (each track's venv: tests.test_tracks, one tool call traced against the local stub)
- Live-model run of the new tracks: UNRESOLVED (missing: API keys; same as M-003)

## Usage
- Wall-clock: 26 Oct 2026, one session
- Tokens: not recorded from /usage in this session

## Blocker
none

## Next action
Owner reviews branch tracks-1.4, adds a work-list item for 1.4.0 if wanted, and pushes.
