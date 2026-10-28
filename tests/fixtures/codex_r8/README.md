# Codex round-8 fixtures (review data)

Copied from Codex's round-8 review of kit 1.4.8 (`kit_harness_marketplace_eaff72a7_src`, 28 Oct 2026,
`r8_fixtures/` and `shell_r8_results.json`; the review stopped at its usage limit after the findings were complete).
All repositories, names and inputs are constructed. The audit reads these files; nothing here is imported or run by
the audit. The runtime tests in `tests/test_audit_r8.py` import copies of them in a throwaway folder, with stand-ins
for the framework constructors and constructed sentinel files.

Changed on copy:
- No `kit_guard.py` is stored. `tests/test_audit_r8.py` writes the shipped helper into a throwaway copy of each
  fixture, so the tests always check the helper of the tree under test.
- The constructed `id_dsa` sentinels and the stand-in `bin/git` are not stored; the runtime tests write them into
  the throwaway folder.

| Fixture | Finding | Expected from 1.4.9 |
|---|---|---|
| builtins_exec, from_builtins_exec | R8-01 | no G1-G3 credit (the exec family by identity), reason `patch.py:<line>` |
| resolve_hand_on | R8-02 | no credit (a repo function stores on its parameter), reason `patch.py:<line>` |
| resolve_direct | R8-02 control | no credit (already so in 1.4.8) |
| class_if_return, class_if_local_return | R8-03 | no credit (the function's namespace is the class, through `if`) |
| class_direct_return | R8-03 control | no credit (already so in 1.4.8) |
| local_control | R8-03 control | 8/8 (options bound as a function local) |
| errors_list, errors_dict | R8-05 | a normal report, no credit (UNRESOLVED option) |
| errors_set | R8-05 control | no credit (already so in 1.4.8) |
| plain | control | 8/8 |
| shell_r8_results.json | R8-04 | both five-wrapper commands refused |
