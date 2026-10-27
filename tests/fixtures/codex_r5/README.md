# Codex round-5 fixtures (review data)

Copied from Codex's round-5 review of kit 1.4.5b (`kit_harness_marketplace_81877ed1_src`, 28 Oct 2026,
`r5_fixtures/`). All repositories, names and inputs are constructed. The audit reads these files; nothing here is
imported or run by the audit.

Changed on copy:
- No `kit_guard.py` is stored. `tests/test_audit_r5.py` writes the shipped helper into a throwaway copy of each
  fixture, so the tests always check the helper of the tree under test.
- `plain/id_dsa` (a constructed sentinel) is not stored; the runtime test writes it into a throwaway folder.
- `positional_executable/agent.py` named an absolute path under Codex's review folder. It is now
  `/constructed/positional_executable/constructed_runner`; the runtime test substitutes a real constructed runner.
  `constructed_runner`, `disclosed.txt` and `ordinary.txt` are not stored.

| Fixture | Finding | Expected from 1.4.6 |
|---|---|---|
| plain | R5-01 control | 8/8 (the helper refuses `cat id_d*` itself) |
| positional_executable, positional_env | R5-02 | no G1-G3 credit (an executable or environment passed positionally) |
| keyword_executable_control | R5-02 control | no credit (already so in 1.4.5b) |
| shadow_shlex | R5-03 | no G1-G3 credit (a standard-library module shadowed beside the guard) |
| sdk_dynamic_output | R5-04 | no G1-G3 credit (another hook returns a named value) |
| sdk_literal_output_control | R5-04 control | no credit (already so in 1.4.5b) |
