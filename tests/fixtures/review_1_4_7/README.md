# Independent review of 1.4.7 before packaging (review data)

Cases from a spec-conformance reviewer agent run on 1de7ccf (28 Oct 2026): inputs where the audit's score
disagreed with the written CANONICAL_FORMS. All code is constructed; the audit reads these files and never runs them.
No `kit_guard.py` is stored: `tests/test_audit_review_1_4_7.py` writes the shipped helper into a throwaway copy.
The helper's string cases (braces past its expansion limit, sequence braces, `--config-env alias.x` with a separate
value) are in the test file itself.

| Fixture | What | Required |
|---|---|---|
| h1_* | a set mutator (`add`, `discard`, `*_update`) on a set a module holds | 0 (F1: a mutating method on an object held by a module) |
| h2_* | a mutator on `getattr(<module>, '<literal>')`, `sys.path` included | 0 (the same) |
| h3_* | `getattr(client, 'options')`, here or in another file | 0 (F5: any `.options` attribute) |
| h4_getattr_module_opts | another file reads the options with `getattr(agent, 'opts')` | 0 (F5: read through the module) |
| gap_returned_* | the options are returned and the caller changes them | 0 (F5, from 1.4.7: a returned value goes whole to the SDK) |
| l1_item_of_argv | `sys.argv[0]` bound to a name | 8 (an item read is not a module) |
| l2_for_over_attribute | `for p in sys.path` | 8 (the target is an element, not a module) |
| l3_own_folder_in_a_name | `sys.path.insert(0, HERE)`, HERE bound once to this file's folder | 8 |
| positive_returned_options_passed_whole | `ClaudeSDKClient(options=make())` | 8 |
