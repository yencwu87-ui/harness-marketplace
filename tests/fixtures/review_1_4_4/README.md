# Independent review fixtures (1.4.4)

Built by an independent adversarial reviewer (a separate Claude agent, 27 Oct 2026) against the canonical-forms
checker before it was sent to Codex. Each scored 8/8 although its guard does not stop the call at run time (the
reviewer ran each hook or tool against framework stand-ins with a harmless input). All constructed; nothing here is
imported or run by the audit. The `kit_guard.py` copies are the shipped helper, unchanged, so that the pinned hash
matches and the run-time patch is what is tested.

| Fixture | Shape |
|---|---|
| f_any, f_crew_str, f_refake | `any`, `str` or `re` redefined in the module |
| f_globals | a tested constant replaced through `globals()` |
| r_kg_patch, r_kg_setattr, r_kg_sitecustom | `kit_guard.refuses` replaced at run time (in the module, with setattr, from another file) |
| f_decorator | a repo decorator replaces the guarded tool |
| f_strands_patch | the Strands handler replaced after the class |
| f_adk_import, f_sdk_import | the tested input rebound by `import ... as` |
| f_maf_alias | the Agent Framework continuation called through an alias before the refusal |
| f_strands_setattr | `cancel_tool` undone with setattr |
| f_sdk_dup | a dict whose duplicate key turns deny into allow |
| f_crew_name | a forged tool-name test (`ctx.agent.name`) |
| r_session | a client built and called in one expression (`requests.Session().get(url)`) |
