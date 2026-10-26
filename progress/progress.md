# Progress

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
