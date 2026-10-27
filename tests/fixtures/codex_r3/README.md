# Codex round-3 fixtures (review data)

Copied from Codex's round-3 review of kit 1.4.3 (`kit_harness_marketplace_0f191c03_src`, 27 Oct 2026,
`r3_fixtures/`). All repositories, names and inputs are constructed. The audit reads these files; nothing here is
imported or run by the audit.

Not copied:
- the constructed `.env` canaries beside some fixtures (the audit never opens them, and this repo's rules forbid
  reading `.env` files);
- `audit_parent_link`, whose `.claude` is an absolute symlink into Codex's workspace. `tests/test_audit_r3.py` builds
  the same shape in a temporary folder (`.claude -> ../constructed_outside`); `constructed_outside/settings.json` is
  the target file Codex used.

| Fixture | Finding | Expected after 1.4.4 |
|---|---|---|
| empty_for, continue_for | R3-01 | no G1-G3 credit (a refusal inside a loop is not canonical) |
| wrong_parameter, overwritten_input, helper_flag, regex_match | R3-02 | no G1-G3 credit |
| noarg_helper, fixed_path_read, fixed_rmtree, fixed_unknown_object | R3-03 | the capability is reported (G3, G2, G3, UNRESOLVED) |
| helper_direct, computed_fixed | R3-03 controls | direct fixed push and its helper form score the same |
| sdk_unknown_servers_wildcard, sdk_unknown_servers_no_allow | R3-04 | UNRESOLVED, with the map-binding reason |
| sdk_scoped_deny | R3-05 | no G2/G3 credit from scoped denies |
| sandbox_excluded, sandbox_ask | R3-06 | no G2 credit while the sandbox has an escape or auto-allow skips the ask |
| constructed_outside | R3-07 | read through a linked `.claude` directory: nothing read, no credit |
| allowlist, same_condition, try_refusal | (judgement) | UNRESOLVED, zero points: deliberate false negatives |
