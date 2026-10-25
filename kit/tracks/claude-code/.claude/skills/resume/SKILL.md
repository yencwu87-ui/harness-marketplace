---
name: resume
description: Start-of-session routine. Use at the start of every work session, or when asked to resume, pick up, or continue the work.
---

# Resume

Do these in order. Keep your notes short.

1. `pwd` and `git status --short`. If there are uncommitted changes you didn't expect,
   stop and report them instead of continuing.
2. `git log --oneline -10`.
3. Read `progress/progress.md` (one screen).
4. Read `progress/feature_list.json` and pick the **first item with `passes: false`**.
   Say its id, title and `done_when` in one line.
5. Run `./init.sh`. If the smoke test fails, fixing that is the item for this session.
6. State a plan of at most 5 steps for this one item, then start.

Rules while working:
- One item only. Do not start a second item in the same session.
- Use the `Explore` agent for lookups rather than reading many files yourself.
- Stop rule: after two failed attempts at the same step, stop and run the `checkpoint`
  skill with the blocker recorded.
