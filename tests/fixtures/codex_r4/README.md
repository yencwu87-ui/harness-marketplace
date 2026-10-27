# Codex round-4 fixtures (review data)

Copied from Codex's round-4 review of kit 1.4.4 (`kit_harness_marketplace_106daa37_src`, 27 Oct 2026,
`r4_fixtures/`). All repositories, names and inputs are constructed. The audit reads these files; nothing here is
imported or run by the audit.

Not copied: `constructed_git`, a throwaway git repository Codex used to show that `git reset --quiet --hard` really
reverts a change. `tests/test_kit_guard.py` checks the helper refuses that command instead.

| Fixture | Finding | Expected from 1.4.5 |
|---|---|---|
| regex_alias_shadow, regex_from_shadow, kit_function_param | R4-01 | no G1-G3 credit (hand-written refusal, or the helper name is rebound) |
| kit_alias_shadow | R4-01 control | no credit (already so in 1.4.4) |
| wrong_capability_argument | R4-02 | no G1-G3 credit (the tested value is not the command) |
| scoped_exit_adk, scoped_exit_crew, scoped_exit_strands, scoped_exit_maf | R4-03 | no G1-G3 credit |
| input_alias_crew, input_alias_sdk, input_alias_adk | R4-04 | no G1-G3 credit |
| cancel_wrong_object, cancel_overwritten_augassign | R4-05 | no G1-G3 credit |
| sdk_wrong_output_key, sdk_top_level_decision, sdk_helper_fallthrough, sdk_helper_decorator, sdk_helper_early_allow, sdk_attr_field | R4-06 | no G1-G3 credit |
| representative_only | R4-07 | no G1-G3 credit (hand-written keywords no longer earn class credit) |
| kit_unchanged | R4-08 | the 1.4.4 helper (copied here unchanged) no longer matches the pinned hash, so no credit; the 1.4.5 helper refuses both inputs |
| native_fs_off, native_fs_on | R4-09 | off: G2 not VERIFIED; on: 8/8 |
