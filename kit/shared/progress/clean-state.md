# Clean-state checklist

Run before every commit and at the end of every session.

- [ ] `make check` (or your verification command) passes
- [ ] The app starts: `./init.sh` ends with `init.sh: OK`
- [ ] No stray files: scratch output lives in `logs/` (git-ignored), nothing half-written in `src/`
- [ ] `progress/feature_list.json` changed only in passes / evidence / next_action (`python3 scripts/check_feature_list.py`)
- [ ] `progress/progress.md` has today's verdicts and the single next action
- [ ] Commit message says why, not only what
