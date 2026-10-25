#!/usr/bin/env python3
"""Claude Code PreToolUse hook that records every tool call to $HARNESS_TRACE and allows it.

It only observes: the agent's own deny rules, hooks and sandbox still decide what runs. The live red team
installs it in the disposable workspace's .claude/settings.local.json, never in your real project.
"""
import json
import os
import sys
import time

data = json.load(sys.stdin) if not sys.stdin.isatty() else {}
path = os.environ.get("HARNESS_TRACE")
if path:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": time.time(), "source": "claude-code-hook", "tool": data.get("tool_name"),
                            "input": data.get("tool_input")}) + "\n")
print("{}")
