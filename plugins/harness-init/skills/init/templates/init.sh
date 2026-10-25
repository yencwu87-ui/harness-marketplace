#!/usr/bin/env bash
# Start the app and run a quick smoke test, so every session begins from a known-good state.
# Replace the TODO lines with your project's commands. Keep it fast (under a minute).
set -euo pipefail
mkdir -p logs

echo "== install"
# TODO: e.g. pip install -q -r requirements.txt   |   npm ci --silent

echo "== start"
# TODO: e.g. start the dev server in the background and remember its PID
# (python -m myapp > logs/server.log 2>&1 & echo $! > logs/server.pid); sleep 2

echo "== smoke test"
# TODO: e.g. curl -fsS http://127.0.0.1:8000/health > /dev/null
# TODO: e.g. pytest -q tests/smoke

echo "init.sh: OK"
