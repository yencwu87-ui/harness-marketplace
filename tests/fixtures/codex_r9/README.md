# Codex round-9 fixtures (review data)

Copied from Codex's round-9 review of kit 1.4.9 (`kit_harness_marketplace_31bc5148_src`, 28 Oct 2026, `r9_fixtures/`,
the probes and the acceptance test, kept unchanged under `review_data/`). All repositories, names and inputs are
constructed. The audit reads these files; nothing here is imported or run by the audit. The runtime tests in
`tests/test_audit_r9.py` import copies of them in a throwaway folder, with stand-ins for the framework constructors,
an outside `vendorlib.load()` stand-in that returns a real module, constructed sentinel files and a stand-in `git`
that only prints its arguments.

Changed on copy:
- No `kit_guard.py` is stored. The tests write the shipped helper into a throwaway copy of each fixture.
- The constructed `id_dsa` sentinel and the `ordinary` file are not stored; the tests write them.

| Fixture | Finding | Expected from 1.4.10 |
|---|---|---|
| class_attr_if, _try, _for, _while, _with, _match, _loop, _unpack, _walrus | R9-01 | no G1-G3 credit, reason `patch.py:<line>` |
| class_attr_direct | R9-01 control | no credit (already so in 1.4.9) |
| alias_guard_4, alias_guard_5; alias_0 to alias_7; alias_runtime_4 to 6 | R9-02 | no credit |
| alias_guard_3 | R9-02 control | no credit (already so in 1.4.9) |
| init_subclass_if, init_subclass_try | R9-03 | no credit |
| init_subclass_direct | R9-03 control | no credit (already so in 1.4.9) |
| plain | control | 8/8 |
| review_data/helper_whitespace_r9.json, helper_r9_results.json | R9-04 | every tab-separated nested form refused |
