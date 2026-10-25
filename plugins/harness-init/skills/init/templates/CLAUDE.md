# <PROJECT NAME>

<One sentence: what this project is and who uses it.>

## Run and test
- Start and smoke-test: `./init.sh`
- Full tests: `<your test command>`
- Lint/format: `<your command>`

## Hard rules
- Never read or print secrets: `.env*`, `*.key`, `*.pem`, credential folders.
- Never push, force-push, `reset --hard` or rewrite history. Commit locally only.
- Never mark work done without checking its `done_when`.
- <Add your project's 1-3 non-negotiables here.>

## How work runs
- Start every session with the `resume` skill. End every session with the `checkpoint` skill.
- One item at a time, from `progress/feature_list.json`, first item with `passes: false`.
- In `feature_list.json` change only `passes`, `evidence` and `next_action`. Never edit, reorder or delete items.
- Stop rule: stop when `done_when` is met, or after two failed attempts at the same step.
  Then record the blocker and its evidence in `progress/progress.md`.
- Use the `explore` agent for lookups and the `verifier` agent before setting `passes: true` (from the harness-core plugin, or `.claude/agents/`).
- Keep long logs in `logs/` and quote only the lines that matter.
- When context runs low, checkpoint and stop cleanly. Never declare an item done to finish faster.
- Before every commit, run the clean-state checklist (`progress/clean-state.md`). Commit messages say why, not only what.
- Record decisions in `DECISIONS.md` (one line each: decision, who, why, date) so later sessions don't reopen them.

## Reporting
Mark every claim VERIFIED (with evidence path), INCORRECT, or UNRESOLVED (say what evidence is missing).

## Compact instructions
When compacting, keep: the current item id, its done_when, files changed, test results, and the next action.
