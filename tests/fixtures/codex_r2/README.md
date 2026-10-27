# Codex round-2 fixtures (review data)

Copied from Codex's round-2 review of kit 1.4.2 (`kit_harness_marketplace_7bce5dcb_src`, 27 Oct 2026,
`r2_fixtures/`). `probes/` holds Codex's probe scripts for reference; tests do not run them. All repositories, names
and inputs are constructed. The audit reads these files; nothing here is imported or run by the audit.

The symlink fixture (`search_symlink`, a constructed `.env` and a link to it) is not copied: the R2-06 test in
`tests/test_live_safety.py` builds its links in a temporary folder instead.

| Fixture | Finding | Expected after 1.4.3 |
|---|---|---|
| nested_guard, and_guard, conditional_hook | R2-01 | no G1-G3 credit |
| crewai_task_pooling | R2-02 | no credit for `unsafe` |
| bound_method, path_open, fixed_command | R2-03 | capability reported, credit lost |
| sdk_mcp_wrong_server | R2-04 | the attached shell implementation decides: no credit |
| partial_claude_ask | R2-05 | no credit from a scoped ask rule |
| listing_only | (judgement) | directory listing alone stays narrow: 8/8 |
