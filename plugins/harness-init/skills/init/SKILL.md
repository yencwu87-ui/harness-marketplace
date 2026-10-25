---
name: init
description: Set up a governed agent harness in this repository - work list with done_when and evidence, progress note, decisions log, clean-state checklist, init.sh, guard script, CLAUDE.md and safe settings. Use when asked to set up, scaffold or initialise a harness.
---

# Set up a harness

The templates are in `templates/` next to this file. Never overwrite an existing file.

1. **Look first.** Run `git status --short` and list which of these already exist: `CLAUDE.md`, `AGENTS.md`,
   `progress/`, `DECISIONS.md`, `init.sh`, `scripts/check_feature_list.py`, `.claude/settings.json`.
   If the `harness-audit` plugin is installed, run its audit and show the score before changing anything.
2. **Show the plan** as a short list: each file you will create, and each existing file you will leave alone.
   Wait for the user's yes.
3. **Create missing files** by copying (not retyping) from the templates:
   - `templates/feature_list.json` → `progress/feature_list.json`
   - `templates/progress.md` and `templates/clean-state.md` → `progress/`
   - `templates/DECISIONS.md` → `DECISIONS.md`
   - `templates/init.sh` → `init.sh` (make it executable)
   - `templates/check_feature_list.py` → `scripts/check_feature_list.py`
   - `templates/CLAUDE.md` → `CLAUDE.md` only if neither CLAUDE.md nor AGENTS.md exists
4. **Settings need care.** If `.claude/settings.json` does not exist, show `templates/.claude/settings.json` and create it
   only after a yes. If it exists, show a proposed merge that **only adds** deny rules; never remove or loosen a rule.
   Tell the user plainly: deny rules stop Claude's own tools, not a script Claude writes; for unattended runs use the
   sandbox setting or a container.
5. **Fill in with the user:** project name and test command in CLAUDE.md; the start and smoke-test commands in init.sh;
   the first three work items, each with a `done_when` someone could check without asking.
6. Run `python3 scripts/check_feature_list.py` and `./init.sh`, then commit locally with a message that says why.
   Do not push.
7. If the audit plugin is installed, re-run it and show the before and after score.
