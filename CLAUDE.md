# Harness Marketplace

A Claude Code plugin marketplace (`.claude-plugin/marketplace.json`, `plugins/`) plus a multi-framework harness kit (`kit/`). This file is for agents working on this repository itself.

## Run and test
- Smoke test: `./init.sh`
- Full check: `make check` (unit tests, self-audit at 80+, plugin validation, work-list guard)

## Hard rules
- Never read or print secrets: `.env*`, `*.key`, `*.pem`, credential folders.
- Never push, force-push, `reset --hard` or rewrite history. Commit locally only.
- Never mark work done without checking its `done_when`.
- Never claim a percentage improvement or a certification. A passing audit means files exist, not that they work.
- Keep plugin `name` fields identical to their marketplace entries.

## How work runs
- Start with the resume routine (`/harness-core:resume`), end with the checkpoint routine (`/harness-core:checkpoint`).
- One item at a time, from `progress/feature_list.json`, first item with `passes: false`.
- In `feature_list.json` change only `passes`, `evidence` and `next_action`.
- Stop rule: stop when `done_when` is met, or after two failed attempts at the same step, and record the blocker in `progress/progress.md`.
- Use the `explore` agent for lookups and the `verifier` agent before setting `passes: true`.
- When context runs low, checkpoint and stop cleanly. Never declare an item done to finish faster.
- Before every commit, run `progress/clean-state.md`. Commit messages say why, not only what.
- Record decisions in `DECISIONS.md`.

## Reporting
Mark every claim VERIFIED (with evidence path), INCORRECT, or UNRESOLVED (say what evidence is missing). Record wall-clock time and usage per accepted item.
