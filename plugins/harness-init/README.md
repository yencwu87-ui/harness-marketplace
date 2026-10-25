# harness-init

`/harness-init:init` sets up a governed harness in your repository, without overwriting anything you already have:

- `progress/feature_list.json`: work items with `done_when` and `evidence`; agents may change only passes, evidence and next_action
- `scripts/check_feature_list.py`: fails if an agent rewrites the list instead of updating it (use in pre-commit or CI)
- `progress/progress.md`, `progress/clean-state.md`, `DECISIONS.md`, `init.sh`
- `CLAUDE.md` (under 200 lines) and `.claude/settings.json` with deny rules for secrets and destructive git, shown to you before anything is written

Deny rules stop Claude's own tools, not scripts it writes. For unattended runs, use the sandbox setting or a container.
