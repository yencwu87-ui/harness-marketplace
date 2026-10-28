# Independent review of 1.4.9 before packaging (review data)

Cases from the second reviewer agent (audit side only; the first stopped after 7 tool calls without reporting a
case). All repositories, names and inputs are constructed; nothing here is run. `expected.json` gives each case's
expected G1-G3 points (a fetch-only tool keeps G3's 2: it can destroy nothing; or `UNRESOLVED`: no point and no MISSING guard check) and the reviewer's label: D1-D8 credit
the written rules withhold, R1-R5 class-object routes the exempt list did not name, grey code-from-text runners
outside the list, O1-O2 over-refusals, and controls. `tests/test_audit_review_1_4_9.py` writes the shipped helper
beside each copy.
