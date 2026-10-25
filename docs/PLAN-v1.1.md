# Plan: v1.1 "evidence you can't fake, attacks on the real path"

Two weaknesses in v1.0, stated plainly:

1. **Acceptance criteria are only as fixed as the last commit.** `check_feature_list.py` compares with HEAD, so a rewrite that gets committed becomes the new baseline. `evidence` is free text that nothing ties to a real run.
2. **The red team mostly tests text.** The kit's `target.py` calls the agents with tools off (Agent SDK, Microsoft Agent Framework) or in a reduced setup. A polite refusal proves nothing about what the agent does with tools.

## Part A: bind criteria to evidence (`tools/harness.py`, stdlib only)

| Piece | What it does |
|---|---|
| Executable criteria | Each `done_when` entry is either `{"id", "run": "<command>"}` (machine check) or `{"id", "human": "<what a person confirms>"}`. A plain string counts as a human check. |
| Criteria fingerprint | `criteria_sha` = SHA-256 of the item's canonical JSON (id, title, done_when). |
| Ledger | `.harness/ledger.jsonl`, append-only and hash-chained: every entry carries the previous entry's hash, so editing history breaks the chain. |
| `harness approve ITEM --by NAME` | A person approves the criteria; the ledger records `criteria_sha`. Changing criteria later needs a new approval. |
| `harness verify ITEM` | The **runner**, not the agent, runs every machine check on a clean tree, stores each log, records exit codes, log hashes, tool versions and the **code fingerprint** (hash of the committed tree excluding `progress/` and `.harness/`), writes an evidence record, chains its hash into the ledger, and only then sets `passes: true`. |
| `harness signoff ITEM CHECK --by NAME` | A named person confirms a human check, bound to the current `criteria_sha`. |
| `harness check` | The guard (pre-commit / CI). Fails if: the chain is broken; an item's criteria differ from its latest approval; an item passes without evidence for the current criteria and code; a log no longer matches its hash; or a human check lacks a sign-off. |
| CI | Re-runs `harness verify --all` on a clean runner instead of trusting the agent's machine; optional signed provenance with GitHub's `attest-build-provenance`. |

## Part B: red-team the real tool path (`redteam-live`)

| Piece | What it does |
|---|---|
| Real entry point | Runs the same command production uses (e.g. `claude -p ... --output-format stream-json` with the project's own `.claude/`, or the track's agent script), not a tools-off chat call. |
| Config parity | Fingerprints settings, agent definitions, instructions and model id; fails if they differ from the recorded production baseline. |
| Disposable workspace | Fresh copy of the repo under a fake HOME; optionally inside the locked-down container. |
| Canaries | A `.env` with a unique token, decoy `~/.ssh` and cloud credentials, a decoy signing key. |
| Indirect injection | Attack text planted where tools read it: README, a test-output file, a fetched-page fixture, a tool-result file. |
| Trace | A PreToolUse hook (Claude Code) or tool callback (Agent SDK, ADK) writes every tool call to a JSONL trace. |
| Egress | A local logging proxy records and blocks hosts outside the allowlist. |
| Deterministic verdicts | Code, not an LLM, decides: no canary read or leaked, no blocked egress, no `git push`, no protected-field change in the work list, repo files outside the task untouched. |
| Positive control | The same attacks against a deliberately naive agent (or the real agent with deny rules removed) must produce violations; if they don't, the suite is blind. |
| Bridges | promptfoo and DeepTeam providers that run the live harness and return the text plus the violations, so attack generation stays theirs and the verdict stays deterministic. |

## Done when

- Unit tests cover: chain tamper, criteria change without approval, pass without evidence, stale evidence after a code change, log tamper, human check without sign-off, a full approve → verify → check cycle.
- Live red team tests: a naive fake agent trips canary, egress and push detectors (positive control); a careful fake agent passes; parity drift is caught.
- Not done here: a run with a live model on each framework (needs API keys). Tracked as M-003.

## 1.2.0 addition: pinned files

Gap found after 1.1: an agent could weaken a test and then run `verify`; the code fingerprint showed the change but the
approval didn't cover the test itself. Approval now hashes the files the criteria depend on (paths named in check
commands, expanded for folders, plus `pins` globs). Any change, removal or new file in a pinned folder needs re-approval.
