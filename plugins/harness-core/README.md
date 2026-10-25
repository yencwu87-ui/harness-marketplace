# harness-core

The working loop for long agent tasks in Claude Code: **resume → build → verify → checkpoint**.

- `/harness-core:resume`: start of session. Reads git status and log, the progress note and the work list, runs `./init.sh`, and picks exactly one item.
- `/harness-core:checkpoint`: end of session. Calls the verifier, updates the work list (passes / evidence / next_action only) and the progress note, records usage, commits locally.
- `explore` agent (Haiku, read-only): lookups that answer with `file:line` evidence.
- `verifier` agent (Sonnet, read-only): checks an item against its `done_when` and returns VERIFIED / INCORRECT / UNRESOLVED.
- Hook: plain `pytest`, `npm test` and `go test` runs show only failures; the full log goes to `logs/last-test-run.log`. Needs `jq`.

Works best after `/harness-init:init` has created the work list and progress files.
