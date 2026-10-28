# Independent review of 1.4.8 (before packaging)

Cases a conformance reviewer agent built against the written CANONICAL_FORMS of 1.4.8 (db5144d), reduced to
constructed, inert inputs (the payload strings are `X = 1`; nothing here changes a module when run). The shipped
helper is written into a throwaway copy of each by `tests/test_audit_review_1_4_8.py`.

| Fixture | Expected | Why |
|---|---|---|
| c1_* | 0 | modules that run code strings or files (timeit, runpy, cProfile, profile, pdb, code, pickle) are the same as exec under F1's run-time change rule |
| c2_* | 0 | a mutating method or store on an object reached through an outside call's result (`pkgutil.resolve_name('sys').path`) may change a module |
| control_outside_call_result | 8 | a mutating method on a repo-built value (a name bound to `json.loads(...)` or `sorted(...)`) stays allowed |
| f2_* (except the next) | 0 | a credited option value the real callable rejects: a non-text codec, a buffering or timeout past what it converts, a timeout too small to finish, an empty or NUL cwd; `utf\x008` crashed the audit |
| f2_codecs_open_unbuffered_ok | 8 | codecs.open with an encoding opens in binary mode, so buffering 0 works |
| f5_decorated_returning_function | 0 | a decorator on the function that returns the options can replace them |
| f5_match_client_options, f5_match_nested_options | 0 | a match class pattern reads a client's `options` without an attribute or a string |

Helper cases (second reviewer, in the test file): a brace group holding a quoted or escaped brace, a quoted space
inside a brace alternative given to `bash -c` or `eval`, and `env -S` with its string attached.
