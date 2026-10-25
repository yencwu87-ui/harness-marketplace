---
name: checkpoint
description: End-of-session routine. Use when an item is done, when stopping after two failed attempts, before a break, or when asked to checkpoint or hand over.
---

# Checkpoint

1. **Verify.** If you think the item is done, call the `verifier` agent (harness-core) with the item id.
   - OVERALL VERIFIED → set `passes: true` and put the evidence path in `evidence`.
   - Otherwise leave `passes: false` and record what failed.
2. **Update `progress/feature_list.json`.** Change only `passes`, `evidence` and
   `next_action` for this item. Then run `python3 scripts/check_feature_list.py`.
3. **Rewrite `progress/progress.md`** (keep it to one screen):
   - date and item id
   - what changed (files)
   - verdicts: VERIFIED / INCORRECT / UNRESOLVED with evidence or what's missing
   - usage: wall-clock time, and the `/usage` session tokens if available
   - blocker, if stopped by the stop rule
   - **the single next action**
4. **Commit** the work and the progress files together, locally, with a message like
   `item <id>: <what changed> (passes: true|false)`. Never push.
5. Reply with the one-line status and the next action.
