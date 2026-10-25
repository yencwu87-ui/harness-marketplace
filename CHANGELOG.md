# Changelog

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
