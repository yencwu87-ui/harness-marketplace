#!/usr/bin/env bash
# Smoke test for the marketplace repo: tools present, tests and audit pass.
set -euo pipefail
command -v python3 >/dev/null
python3 -m unittest discover -s tests -q
python3 plugins/harness-audit/skills/audit/scripts/audit.py . --min 80 >/dev/null
echo "init.sh: OK"
