# harness-audit 1.4.1 (pinned, for the base comparison)

`audit.py.txt` is `plugins/harness-audit/skills/audit/scripts/audit.py` at commit `24bc1da` (1.4.1), byte for byte:
git blob `c030f56a9fcc36c0a94bbfe67850ef844f1a343d`, sha256
`79c2421797164777a726107e68e243d7bd57a57f5cee6ce2d17b3aefc8d9b171`. `tests/test_audit_fairness.py` checks both and
fails on a mismatch. It is stored as `.txt` so nothing indexes or imports it as code; the test copies it to a
temporary `.py` and runs it on the round-1 fixtures. Vendored because CI checks out shallow clones and downloads
have no `.git`, so `git show 24bc1da:...` cannot work there.
