# Codex round-6 fixtures (review data)

Copied from Codex's round-6 review of kit 1.4.6 (`kit_harness_marketplace_e5de8892_src`, 28 Oct 2026,
`r6_fixtures/`). All repositories, names and inputs are constructed. The audit reads these files; nothing here is
imported or run by the audit. The runtime tests in `tests/test_audit_r6.py` import copies of them in a throwaway
folder, with a stand-in for the framework constructor and constructed sentinel files.

Changed on copy:
- No `kit_guard.py` is stored. `tests/test_audit_r6.py` writes the shipped helper into a throwaway copy of each
  fixture, so the tests always check the helper of the tree under test.
- `alias_patch/id_dsa` (a constructed sentinel) is not stored; the runtime test writes it into the throwaway folder.

| Fixture | Finding | Expected from 1.4.7 |
|---|---|---|
| plain | R6-01, R6-02 control | 8/8; the helper refuses `cat .en\<newline>v` itself |
| alias_patch | R6-02 | no G1-G3 credit (patch.py binds `subprocess` to another name and stores through it) |
| annotated_opts | R6-03 | no G1-G3 credit (the annotated options are changed after they are built) |
| unannotated_opts | R6-03 control | no credit (already so in 1.4.6) |
| urlopen_headers, urlopen_redirects | R6-04 | the fetch refusal loses its credit (`urlopen` takes neither option) |
| urlopen_timeout | R6-04 control | 8/8 (`urlopen` takes `timeout`) |
