# Changelog

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
