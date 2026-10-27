# Codex round-7 fixtures (review data)

Copied from Codex's round-7 review of kit 1.4.7 (`kit_harness_marketplace_855ccb57_src`, 28 Oct 2026,
`r7_fixtures/`). All repositories, names and inputs are constructed. The audit reads these files; nothing here is
imported or run by the audit. The runtime tests in `tests/test_audit_r7.py` import copies of them in a throwaway
folder, with stand-ins for the framework constructors and constructed sentinel files.

Changed on copy:
- No `kit_guard.py` is stored. `tests/test_audit_r7.py` writes the shipped helper into a throwaway copy of each
  fixture, so the tests always check the helper of the tree under test.
- The constructed `id_dsa` sentinels are not stored; the runtime test writes one into the throwaway folder.

| Fixture | Finding | Expected from 1.4.8 |
|---|---|---|
| getattr_hand_on, getattr_binding, getattr_default | R7-01 | no G1-G3 credit (getattr's target is a module) |
| direct_control, list_item, dict_key, param_shadow, getattr_module_mutator, getattr_path_append | R7-01 controls | no credit (already so in 1.4.7) |
| capital_module | R7-04 bound | no credit: `path` is a lower-case module renamed `Path`, outside the class exception |
| class_opts, class_annotated_opts | R7-02 | no credit (options bound in a class namespace) |
| plain_opts_control | R7-02 control | 8/8 (module-level options) |
| check_output_check, check_output_capture | R7-03 | no credit (`check_output` raises for both options) |
| check_output_plain | R7-03 control | 8/8 |
| class_to_repo_function | R7-04 | 8/8 (a capitalised outside class may be passed anywhere) |
| class_to_outside_function, plain | controls | 8/8 |
