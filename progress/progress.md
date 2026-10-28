# Progress

**Updated:** 28 Oct 2026  **Item:** 1.4.10, Codex round-9 fix round by class (coordinator brief, not a work-list item)  **Status:** passed locally except the 12 port tests, awaiting the coordinator's runs (port tests, Python 3.12, SDK-engine smoke) and Codex round 10

## What changed
- plugins/harness-audit/skills/audit/scripts/audit.py (1.4.10): one namespace walker (`_namespace`, `_own_nodes`, `_bindings`, `_lookup`, `_binding_source`) used by every rule; R9-01 class attributes and R9-03 `__init_subclass__` read in a class's whole namespace; R8-02/R9-02 alias status over every binding form up to 64 steps, then held; every analysis bound fails closed (table in DECISIONS.md); the independent review's 14 cases; CANONICAL_FORMS and SKILL.md
- kit/shared/kit_guard.py (version 7, copy synced, re-pinned): blanks and separators read as a shell does, other control characters and non-ASCII spaces refused, bounds refuse, the independent review's helper cases
- tests: test_audit_r9.py, test_bounds.py, test_audit_review_1_4_10.py, test_helper_review_1_4_10.py; fixtures codex_r9; fairness `c` helper copies refreshed

## Verdicts
- R9-01 to R9-04 and the generated class suites red on 31bc5148 (5,097 failing subtests; 42 more in the neighbour suite; bounds suite 11 failures and 8 errors), green at HEAD: VERIFIED (deliver/1.4.10/logs/red_*_vs_31bc5148.log, unittest_full/)
- Independent reviews (audit 14 cases, helper 10 cases) red before the fixes, green at HEAD: VERIFIED (deliver/1.4.10/logs/red_audit_review_vs_0bc4f9b.log, red_helper_review_vs_1baab4c.log)
- Fairness a=8 b=0 c=2 on 8 tracks, starters 8/8: VERIFIED (deliver/1.4.10/logs/test_audit_fairness.log)
- Self-audit of clean exports: 83 for 31bc5148 and HEAD: VERIFIED (deliver/1.4.10/logs/audit_self_clean_export.log)
- 12 TCP-bind tests: UNRESOLVED (sandbox refuses the bind; same 12 as 1.4.9, deliver/1.4.10/logs/failing_after.txt)
- Pinned SDK-engine smoke and Python 3.12: UNRESOLVED (not available here; the coordinator runs them)

## Usage
- Wall-clock: 28 Oct 2026, 12:47 to about 14:20 +08 (one session, packaging included)
- Tokens: not available to this headless session

## Blocker
none

## Next action
Coordinator runs the 12 port tests, Python 3.12 and the SDK-engine smoke, and sends the package to Codex for round 10.

---
**Updated:** 28 Oct 2026  **Item:** 1.4.9, Codex round-8 fix round (coordinator brief, not a work-list item)  **Status:** passed locally except the 12 port tests, awaiting the coordinator's runs (port tests, SDK-engine smoke) and Codex round 9

## What changed
- kit/shared/kit_guard.py (version 6, copy synced, re-pinned): a nested command past four levels is refused as destructive and secret; a word equal to the text being read is not read again
- plugins/harness-audit/skills/audit/scripts/audit.py (1.4.9): F1 exec family by identity (names in every binding form, builtins module, code-from-text list, pkgutil and pydoc as module sources); repo parameters not exempt (self/cls of followed classes and two framework contract stores excepted; what self holds checked by attribute name); F5 class namespace through compound statements, unreadable hooks UNRESOLVED; F2 and settings never crash on a literal, tighter value rules; CANONICAL_FORMS and SKILL.md
- tests: test_audit_r8.py, test_audit_review_1_4_9.py, test_sdk_engine_smoke.py (pinned, skips without claude-agent-sdk 0.2.174 and sandbox-exec); fixtures codex_r8, review_1_4_9; llm_stub STUB_INPUT; fairness `c` helper copies refreshed

## Verdicts
- R8-01 to R8-05 red on eaff72a (2071 cases in 24 tests), green at HEAD: VERIFIED (deliver/1.4.9/logs/red_r8_vs_eaff72a.log, unittest_full_sandboxed.log)
- Independent review cases red at 6257461 (62 of 70), green at HEAD: VERIFIED (deliver/1.4.9/logs/red_review_1_4_9_vs_6257461.log)
- Fairness a=8 b=0 c=2 on 8 tracks, starters 8/8: VERIFIED (deliver/1.4.9/logs/test_audit_fairness.log)
- Self-audit of a clean export: 83 for eaff72a and HEAD: VERIFIED (deliver/1.4.9/logs/audit_self_clean_export.log)
- 12 TCP-bind tests: UNRESOLVED (sandbox refuses the bind; same 12 as 1.4.8, deliver/1.4.9/logs/failing_after.txt)
- Pinned SDK-engine smoke: UNRESOLVED (written, skips here: nothing installed; the coordinator runs it)
- init.sh: UNRESOLVED (stopped at the 10-minute tool limit; it runs the same suite)
- Python 3.12 run: UNRESOLVED (3.14.6 only here)

## Usage
- Wall-clock: 28 Oct 2026, 08:53 to about 10:15 +08 (one session, packaging included)
- Tokens: not available to this headless session

## Blocker
none

## Next action
Coordinator runs the port tests and the pinned SDK-engine smoke, and sends the package to Codex for round 9.

---

**Updated:** 28 Oct 2026  **Item:** 1.4.8, Codex round-7 fix round (coordinator brief, not a work-list item)  **Status:** passed locally except the 12 port tests, awaiting the coordinator's run and Codex round 8

## What changed
- kit/shared/kit_guard.py (version 5, copy synced, re-pinned): brace groups expanded in destructive commands (each alternative and the shell's in-a-row reading, bounded); a word mixing an unquoted `{` with a quoted or escaped brace refused; brace readings and `env -S` strings read as nested shells
- plugins/harness-audit/skills/audit/scripts/audit.py (1.4.8): F1 closed list of module-value uses (getattr/hasattr targets, arguments, containers, keys, returns, attributes, defaults withhold credit), bounded capitalised-class exception, code-running modules, mutators through outside call results; F5 options only at module level or as a function local, no decorated or class-defined options function, match patterns; F2 per-callable lists (check_output) and value rules; CANONICAL_FORMS and SKILL.md
- tests: test_audit_r7.py, test_audit_review_1_4_8.py; fixtures codex_r7, review_1_4_8; fairness `c` helper copies refreshed

## Verdicts
- R7-01 to R7-04 and the brace observation red on 855ccb5 (1308 cases), green at HEAD: VERIFIED (deliver/1.4.8/logs/red_r7_vs_855ccb5.log, unittest_full_sandboxed.log)
- Independent review cases red at 5397389 (10) and 0b2933f (33), green at HEAD: VERIFIED (deliver/1.4.8/logs/red_review_1_4_8_a_vs_5397389.log, red_review_1_4_8_b_vs_0b2933f.log)
- Fairness a=8 b=0 c=2 on 8 tracks, starters 8/8: VERIFIED (deliver/1.4.8/logs/test_audit_fairness.log)
- Self-audit of a clean export: 83: VERIFIED (deliver/1.4.8/logs/audit_self_clean_export.log)
- 12 TCP-bind tests: UNRESOLVED (sandbox refuses the bind; the coordinator runs them)
- Pinned SDK-engine smoke for R5-04: UNRESOLVED (nothing installed, as the brief says)
- Python 3.12 run: UNRESOLVED (no 3.12 interpreter on this machine; 3.14.6 only)

## Usage
- Wall-clock: 28 Oct 2026, 07:33 to about 08:45 +08 (one session, packaging included)
- Tokens: not available to this headless session

## Blocker
none

## Next action
Coordinator runs the port tests, takes the SDK install question to the owner, and sends the package to Codex for round 8.

---

**Updated:** 28 Oct 2026  **Item:** 1.4.7, Codex round-6 fix round (coordinator brief, not a work-list item)  **Status:** passed locally except the 12 port tests, awaiting the coordinator's run and Codex round 7

## What changed
- kit/shared/kit_guard.py (version 4, copy synced, re-pinned): backslash-newline continuations joined as the shell does and checked joined and unjoined; brace overflow refused, brace sequences expanded; `--config-env alias.x` with a separate value
- plugins/harness-audit/skills/audit/scripts/audit.py (1.4.7): F1 module objects (no binding, handing on or storing through a module anywhere in the tree; sys.modules, importlib, __import__, namespaces, frames); F5 every binding form of the SDK options, other files, `.options`, returned options; F2 per-callable fetch options; CANONICAL_FORMS and SKILL.md
- tests: test_audit_r6.py, test_audit_review_1_4_7.py; fixtures codex_r6, review_1_4_7; fairness `c` helper copies refreshed

## Verdicts
- R6-01 to R6-04 red on e5de889 (238 cases), green at HEAD: VERIFIED (deliver/1.4.7/logs/red_r6_vs_e5de889.log, unittest_full_sandboxed.log)
- Independent review cases red at 1de7ccf (25), green at HEAD: VERIFIED (deliver/1.4.7/logs/red_review_1_4_7_vs_1de7ccf.log)
- Fairness a=8 b=0 c=2 on 8 tracks, starters 8/8: VERIFIED (deliver/1.4.7/logs/test_audit_fairness.log)
- Self-audit of a clean export: 82, down from 89 at e5de889, because kit/shared/target.py imports importlib.util (F1 module objects, tree-wide): VERIFIED (deliver/1.4.7/logs/audit_self_clean_export.log)
- 12 TCP-bind tests: UNRESOLVED (sandbox refuses the bind; the coordinator runs them)
- Pinned SDK-engine smoke for R5-04: UNRESOLVED (no SDK installed; nothing installed, as the brief says)

## Usage
- Wall-clock: 28 Oct 2026, 04:04 to about 05:15 +08 (one session, packaging included)
- Tokens: not available to this headless session

## Blocker
none

## Next action
Coordinator runs the port tests, takes the SDK install question to the owner, and sends the package to Codex for round 7.

---

**Updated:** 28 Oct 2026  **Item:** 1.4.6, Codex round-5 fix round (coordinator brief, not a work-list item)  **Status:** passed locally except the 12 port tests, awaiting the coordinator's run and Codex round 6

## What changed
- kit/shared/kit_guard.py (version 3, copy synced): imports nothing; globs over-approximated; . and .. resolved between .config and gcloud; %-escapes decoded up to three times
- plugins/harness-audit/skills/audit/scripts/audit.py (1.4.6): F2 signature binding and per-capability option lists; F1 standard-library shadows, wider tampering forms, skipped-folder imports, startup hooks in any form, unchecked kit_guard pyc; F5 strict SDK hook outputs, hooks-dict keys, options used after build; CANONICAL_FORMS and SKILL.md
- kit/tracks/claude-agent-sdk/agent.py: deny_secrets returns the deny literal directly
- tests: test_audit_r5.py, test_audit_review_1_4_6.py, glob table in test_kit_guard.py; fixtures codex_r5, review_1_4_6

## Verdicts
- R5-01 to R5-04 red on 81877ed, green at HEAD: VERIFIED (deliver/1.4.6/logs/red_r5_vs_81877ed.log, unittest_full_sandboxed.log)
- Independent review cases red at c9ad575, green at HEAD: VERIFIED (deliver/1.4.6/logs/red_review_1_4_6_vs_c9ad575.log)
- Fairness a=8 b=0 c=2 on 8 tracks, starters 8/8: VERIFIED (deliver/1.4.6/logs/test_audit_fairness.log)
- 12 TCP-bind tests: UNRESOLVED (sandbox refuses the bind; the coordinator runs them)
- `*.py` and `src/*.json` refused, against the brief's examples: INCORRECT against the brief as written; recorded in DECISIONS for the owner
- Real SDK engine smoke for R5-04: UNRESOLVED (no engine or key here)

## Usage
- Wall-clock: 28 Oct 2026, about 00:50 to 01:55 +08 (one session, packaging included)
- Tokens: not available to this headless session

## Blocker
none

## Next action
Coordinator runs the port tests and sends the package to Codex for round 6.

---

**Updated:** 28 Oct 2026  **Item:** 1.4.5b, one regression found after delivery (coordinator brief, not a work-list item)  **Status:** passed locally except the 12 port tests, awaiting the coordinator's run outside the sandbox

## What changed
- kit/tracks/claude-agent-sdk/agent.py: new first PreToolUse hook `trace_tool_call` (trace only, deep copy, returns {}); the trace write left `deny_secrets`; `guard_tool_input` unchanged
- kit/tracks/claude-agent-sdk/harness_track.json: tool_hook.where -> agent.py:trace_tool_call; README; CHANGELOG under 1.4.5; DECISIONS
- tests/test_live_safety.py: two port-free tests on hook order and the trace of a refused attempt

## Verdicts
- Cause (guard refuses before the trace write): VERIFIED (red on 67ca076: deliver/1.4.5b/logs/red_vs_67ca076.log)
- New tests green after the fix: VERIFIED (deliver/1.4.5b/logs/unittest_after_fix.log)
- Other full tracks: no refusal ahead of the trace write (they have no code refusal; claude-code traces from a settings hook that only observes): VERIFIED by reading the starters
- Audit credit unchanged: SDK starter check lines identical to 67ca076, self-audit 93, fairness a=8 b=0 c=2, starters 8/8: VERIFIED (deliver/1.4.5b/logs/audit_*.log, test_audit_fairness.log)
- PresetIntegration SDK test and the other 11 port tests: UNRESOLVED here (sandbox refuses bind); the coordinator runs them

## Blocker
none

## Next action
Coordinator runs the 12 port tests outside the sandbox, then Codex round 5.

---

**Updated:** 28 Oct 2026  **Item:** 1.4.5, Codex round-4 fix round (coordinator brief, not a work-list item)  **Status:** passed locally, awaiting Codex round 5 and owner review

## What changed
- plugins/harness-audit/skills/audit/scripts/audit.py (1.4.5): code refusals earn credit only through the kit helper (`from kit_guard import refuses`, first statement, parameter passed straight as the operation argument) or a framework's exact contract; hand-written refusals UNRESOLVED; classes from the helper; filesystem.disabled voids the Read-deny binding; can_use_tool read
- kit/shared/kit_guard.py version 2 (pinned by sha256) and its copy; tests/test_kit_guard.py generated class table
- kit/tracks/claude-agent-sdk/agent.py: guard_tool_input (contract form) and deny_secrets (deep copy)
- tests/test_audit_r4.py, tests/test_audit_review_1_4_5.py, Round4NearMisses, tests/fixtures/codex_r4/, tests/fixtures/fairness_1_4_5/

## Verdicts
- R4-01 to R4-09 fixture tests: VERIFIED (deliver/1.4.5/logs/red_r4_findings_vs_1.4.4.log red on 1.4.4: 23 failures; green in deliver/1.4.5/logs/full_suite_head_sandboxed.log)
- Independent review seams: VERIFIED closed (deliver/1.4.5/logs/red_independent_review_1_4_5.log red: 23; green in the full run). The reviewer built no bypasses itself: UNRESOLVED whether more exist
- Fairness matrix a=8 b=0 c=2 on 8 tracks (c in helper form where the original is hand-written), kit starters 8/8: VERIFIED (test_audit_fairness)
- Tests that need a TCP bind (12): UNRESOLVED in this session (the sandbox refuses bind)
- Installed-framework smokes, live model runs, real Claude Code sandbox: UNRESOLVED (not installed here; no API keys, as M-003)

## Usage
- Wall-clock: Tue Oct 27 23:07:08 +08 2026 to Wed Oct 28 00:04:27 +08 2026 (one session)
- Tokens: not available to this headless session

## Blocker
none

## Next action
Coordinator verifies the Codex package and starts round 5.

---

**Updated:** 27 Oct 2026  **Item:** 1.4.4, Codex round-3 fix round (coordinator brief, not a work-list item)  **Status:** passed locally, awaiting Codex round 4 and owner review

## What changed
- plugins/harness-audit/skills/audit/scripts/audit.py (1.4.4): credit only canonical guard forms (CANONICAL_FORMS, --canonical-forms), fail-closed reach, unreadable MCP maps UNRESOLVED, one rule standard for SDK and settings, sandbox credit only without escapes, every read contained in the root
- kit/shared/kit_guard.py (pinned by sha256) and its copy in kit/tracks/claude-agent-sdk; the SDK starter hook leads with canonical refusals
- init template and Claude Code track settings: allowUnsandboxedCommands false
- tests/test_audit_r3.py, tests/test_audit_nearmiss.py (round-3 families), tests/fixtures/codex_r3/

## Verdicts
- R3-01 to R3-07 evidence-to-close tests: VERIFIED (logs/1.4.4/red_r3_findings.log red on 1.4.3; green in the full run)
- Independent review's 13 bypasses: VERIFIED closed (logs/1.4.4/red_independent_review.log red, then green)
- Fairness matrix unchanged a=8 b=0 c=2 on 8 tracks, kit starters 8/8: VERIFIED (logs/1.4.4/fairness_and_fixtures_after.txt)
- Tests that need a TCP bind (12): UNRESOLVED in this session (the sandbox refuses bind; the same 12 fail on 1.4.3 here)
- Installed-framework smokes, live model runs: UNRESOLVED (frameworks not installed here; no API keys, as M-003)
- This repo's own .claude/settings.json lacks allowUnsandboxedCommands false, so its self-audit G2 is UNRESOLVED (93/100): owner decision

## Usage
- Wall-clock: 27 Oct 2026 19:15 to about 20:25 +08 (one session)
- Tokens: not available to this headless session

## Blocker
none

## Next action
Coordinator verifies the Codex package and starts round 4.

---

**Updated:** 27 Oct 2026  **Item:** 1.4.3, Codex round-2 fix round (coordinator brief, not a work-list item)  **Status:** passed locally, awaiting Codex round 3 and owner review

## What changed
- plugins/harness-audit/skills/audit/scripts/audit.py (1.4.3): refusal analysis by OR-branch with enclosing conditions, scope-aware Claude Code rules, SDK MCP server binding, reach that never drops a capability, no secret files or outward symlinks read
- kit/tracks/claude-agent-sdk/agent.py: search_code and the hook check symlink targets
- tests/test_audit_r2.py, tests/test_audit_nearmiss.py, tests/test_live_safety.py (R2-06), tests/fixtures/codex_r2/, tests/fixtures/audit_1_4_1/

## Verdicts
- R2-01 to R2-06 evidence-to-close tests: VERIFIED (logs/r143/red_r2_findings.log red on 1.4.2; green in the full run)
- Shallow-clone CI defect: VERIFIED (logs/r143/red_ci_shallow_clone.log, logs/r143/green_ci_shallow_clone.log)
- Fairness matrix unchanged a=8 b=0 c=2 on 8 tracks: VERIFIED (logs/r143/fairness_matrix_after.txt)
- Installed-framework smokes, live model runs: UNRESOLVED (frameworks not installed here; no API keys, as M-003)

## Usage
- Wall-clock: 27 Oct 2026 18:30 to about 19:00 +08 (one session)
- Tokens: not available to this headless session

## Blocker
none

## Next action
Coordinator verifies the Codex package and starts round 3.

---

**Updated:** 26 Oct 2026  **Item:** 1.4.0 tracks (owner request, not yet a work-list item)  **Status:** passed locally, awaiting owner review

## What changed
- kit/tracks/{langgraph,openai-agents-sdk,crewai,strands-agents}: starters, pinned requirements, trace hooks, READMEs
- kit/tracks/{llamaindex,pydantic-ai,smolagents,haystack,dspy,agno,mastra,vercel-ai-sdk}: assess-only spec + README
- kit/tracks/*/harness_track.json and kit/tracks/TRACK_SPEC.md: the track spec
- tools/redteam_live/redteam_live.py (+ synced copies): "track" presets in live.json
- tests/test_tracks.py, tests/llm_stub.py: spec checks and offline smoke tests

## Verdicts
- Spec checks: VERIFIED (python3 -m unittest discover -s tests: OK, smoke tests skipped without frameworks)
- Smoke test per new full track: VERIFIED (each track's venv: tests.test_tracks, one tool call traced against the local stub)
- Live-model run of the new tracks: UNRESOLVED (missing: API keys; same as M-003)

## Usage
- Wall-clock: 26 Oct 2026, one session
- Tokens: not recorded from /usage in this session

## Blocker
none

## Next action
Owner reviews branch tracks-1.4, adds a work-list item for 1.4.0 if wanted, and pushes.
