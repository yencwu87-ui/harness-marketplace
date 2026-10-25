#!/usr/bin/env bash
# PreToolUse hook: when Claude runs a plain test command, show it only failures.
# Based on the example in https://code.claude.com/docs/en/costs
# Needs: jq. If jq is missing the hook does nothing.
set -u
input=$(cat)
command -v jq >/dev/null 2>&1 || { echo "{}"; exit 0; }
cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty')

# Only rewrite simple test runs (no pipes, redirects, chaining or substitution).
pattern='^(npm test|pytest|python -m pytest|go test)( [^;&|<>`$#\\[:cntrl:]]*)?$'
if [[ "$cmd" =~ $pattern ]]; then
  mkdir -p logs
  filtered="(set -o pipefail; $cmd 2>&1 | tee logs/last-test-run.log | grep -A 5 -E '(FAIL|ERROR|error:|Error:)' | head -100; s=\${PIPESTATUS[0]}; [ \$s -eq 0 ] && echo 'All tests passed (full log: logs/last-test-run.log)'; exit \$s)"
  printf '%s' "$input" | jq --arg f "$filtered" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", updatedInput: (.tool_input + {command: $f})}}'
else
  echo "{}"
fi
