# Fairness matrix, 1.4.5 helper forms

From 1.4.5 hand-written refusals earn no credit (`audit.py --canonical-forms`, F7). Four of Codex's round-1 `c`
fixtures (`tests/fixtures/codex_r1/<track>/c`: Claude Agent SDK, Google ADK, CrewAI, Strands) guard the shell with a
hand-written predicate, so they now score 0 (UNRESOLVED) while the other four tracks keep 2 through an approval.
That difference is the mechanism, not the guard behaviour.

These folders are the same `c` fixtures with the same guard behaviour (shell guarded, web fetch not) written with the
kit's helper in each framework's contract form, so the matrix keeps measuring "same behaviour, same points". The
originals stay unchanged and are asserted as the documented false negatives in `tests/test_audit_fairness.py`.
