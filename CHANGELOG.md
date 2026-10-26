# Changelog

## 1.4.0 (26 Oct 2026)
- **Four more tracks, supported (full):** LangGraph (langgraph 1.2.17), OpenAI Agents SDK (openai-agents 0.24.0), CrewAI (crewai 1.15.30) and AWS Strands Agents (strands-agents 1.62.0). Each has a starter wired to `shared/target.py`, a pinned `requirements.txt`, model calls that can point at a gateway (base URL from the environment), and a tool-call trace for the live red team that uses the framework's own hook (LangChain callback, `RunHooks`, before-tool-call hook, `BeforeToolCallEvent`).
- **Eight assess-only tracks:** LlamaIndex, Pydantic AI, smolagents, Haystack, DSPy, Agno, Mastra and Vercel AI SDK. Each has a spec file and a short README so an assessor can detect and audit a harness built on it. The kit ships no starter or trace hook for them yet.
- **Track spec:** every track has a `harness_track.json` (`harness-track/1`, see `kit/tracks/TRACK_SPEC.md`), the four existing tracks included.
- **Live red team:** `"track": "<id>"` in `live.json` fills in that track's agent command. Code tracks write their own trace, so the Claude Code hook is not installed for them.
- **Offline smoke tests:** `tests/test_tracks.py` drives one tool call through each new track against `tests/llm_stub.py` (a local Anthropic/OpenAI-shaped stub on 127.0.0.1) and checks that the trace recorded it. The tests skip when a framework isn't installed.
- harness-redteam 1.4.0 (its skill names the track presets). `make setup` uses `--pre` only for Microsoft Agent Framework. AutoGen and Semantic Kernel are noted under Microsoft Agent Framework rather than given tracks of their own.

## 1.3.0 (25 Oct 2026)
- **Independent re-execution:** `harness reverify` re-runs every passing item's checks on the current machine, writes nothing, and fails if any fail. The CI template now runs `check` then `reverify` and fails properly (1.1's template did not).
- **Environment pinning:** dependency lockfiles (requirements, poetry, uv, npm, pnpm, yarn, Cargo, go.sum, …) are pinned automatically; evidence records fingerprint git-ignored local files that could affect tests.
- **Forced egress for the live red team:** `"isolation": "netns"` runs the agent in a Linux network namespace with no network except the logging proxy (through `bridge.py`); `"docker"` does the same in a container with `--network none` (experimental). The self-test now proves isolation: a direct connection is blocked and a proxied one is logged.
- **Runtime parity:** the served model, tools and MCP servers are read from the agent's own init event; a model that differs from production is a violation.
- `docs/HARDENING.md` (CODEOWNERS, branch protection, signed commits, CI proof) and `docs/LIVE-RUN.md` (the first live run).
- 37 tests.

## 1.2.0 (25 Oct 2026)
- **Pinned files:** approval now records hashes of every file the criteria depend on: files named in check commands (pytest node ids included) plus optional `pins` globs (e.g. fixtures). `verify` refuses and `check` fails if a pinned file changed, disappeared or a new one appeared in a pinned folder, until a person approves again. Closes the "weaken the test, then verify" gap. 5 new tests (18 in total for the binding).

## 1.1.0 (25 Oct 2026)
- **Evidence binding:** `tools/harness.py` (approve / verify / signoff / retire / check / status). Executable `done_when` checks, criteria fingerprints, hash-chained ledger, code fingerprint, runner-only passes. 13 tests.
- **Live red team:** `tools/redteam_live/` runs generated attacks through the real agent command with canaries, a tool trace, a trap remote and an egress proxy; deterministic verdicts; config parity against a production baseline; detector self-test. promptfoo and DeepTeam bridges. 5 tests.
- Trace hooks in the Claude Agent SDK, Google ADK and Microsoft Agent Framework tracks.
- harness-audit 1.1.0: new checks S8 (criteria bound to evidence) and E4 (red team on the real tool path).
- CI runs all unit tests, the copy-sync check and the live self-test.

## 1.0.2
- harness-audit finds decisions logs in nested folders.

## 1.0.1
- harness-audit: fewer false passes (I3, P3, P4, C3); one directory walk, about 2 s on large repos.

## 1.0.0
- Four Claude Code plugins (audit, init, core, redteam) and the multi-framework kit.
