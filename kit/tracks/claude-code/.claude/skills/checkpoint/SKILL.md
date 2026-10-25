---
name: checkpoint
description: End-of-session routine. Use when an item is done, when stopping after two failed attempts, before a break, or when asked to checkpoint or hand over.
---

# Checkpoint

1. **Verify with the runner, not by hand.** Commit your work first (the runner refuses a dirty tree), then run
   `python3 scripts/harness.py verify <id>`. It runs every machine check, stores the logs, chains their hashes into
   `.harness/ledger.jsonl` and sets `passes` only if every check passed and every human check is signed off.
   If `scripts/harness.py` is missing, call the `verifier` agent and leave `passes: false`.
2. **Check the binding.** Run `python3 scripts/harness.py check`. Never edit `passes`, `evidence` or `done_when` by hand.
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
