"""Claude Agent SDK track: the same harness loop as the Claude Code track, but in your own Python.

  python agent.py --repo /path/to/your/repo     work on the next failing item, then stop
  python agent.py --ask "question"              one-shot answer, no tools (used by the test suites)

What it shows:
  - picks ONE item from progress/feature_list.json (first with passes: false)
  - model and effort chosen once, at start
  - a PreToolUse hook that refuses to read secrets (file tools and shell)
  - an OS-level sandbox for shell commands (Claude Code's sandbox; see README for platform support)
  - a cheap Haiku "explore" subagent for lookups
  - bounded turns and budget, then prints usage and appends it to progress/usage.log
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import time
from pathlib import Path

from claude_agent_sdk import (
    AgentDefinition,
    AssistantMessage,
    ClaudeAgentOptions,
    HookMatcher,
    ResultMessage,
    TextBlock,
    query,
)

MODEL = os.environ.get("KIT_MODEL", "opus")          # alias or full id, e.g. claude-opus-5-5
EFFORT = os.environ.get("KIT_EFFORT", "medium")      # low | medium | high | xhigh | max
SECRET = re.compile(r"(^|/)(\.env(\..*)?|.*\.(key|pem)|\.ssh/.*|\.aws/.*)$")


async def deny_secrets(input_data, tool_use_id, context):
    """PreToolUse hook: refuse file reads of secret paths and shell commands that name them."""
    tool = input_data.get("tool_name", "")
    args = input_data.get("tool_input", {}) or {}
    target = args.get("file_path") or args.get("path") or ""
    command = args.get("command", "")
    hit = (target and SECRET.search(target)) or (
        command and re.search(r"\.env\b|\.pem\b|\.key\b|\.ssh/|\.aws/", command)
    )
    if hit:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"{tool} on a secret path is not allowed by the harness.",
            }
        }
    return {}


def next_item(repo: Path) -> dict | None:
    data = json.loads((repo / "progress/feature_list.json").read_text())
    return next((i for i in data["items"] if not i.get("passes")), None)


def options(repo: Path, tools: bool = True) -> ClaudeAgentOptions:
    common = dict(model=MODEL, effort=EFFORT, cwd=str(repo))
    if not tools:
        return ClaudeAgentOptions(**common, tools=[], max_turns=1)
    return ClaudeAgentOptions(
        **common,
        system_prompt={
            "type": "preset",
            "preset": "claude_code",
            "append": (
                "Work on exactly one item. Stop when its done_when is met or after two failed attempts "
                "at the same step. In progress/feature_list.json change only passes, evidence and "
                "next_action. Mark claims VERIFIED / INCORRECT / UNRESOLVED with evidence."
            ),
        },
        setting_sources=["project"],          # loads the repo's CLAUDE.md and .claude/ if present
        allowed_tools=["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Agent"],
        disallowed_tools=["Bash(git push *)", "Bash(git reset --hard *)", "Bash(rm -rf *)"],
        permission_mode="acceptEdits",
        sandbox={"enabled": True, "autoAllowBashIfSandboxed": True},
        hooks={"PreToolUse": [HookMatcher(matcher="Read|Edit|Write|Bash|Grep|Glob", hooks=[deny_secrets])]},
        agents={
            "explore": AgentDefinition(
                description="Read-only lookups. Returns evidence as file:line.",
                prompt="Answer the lookup with at most 10 evidence lines (path:line). Never edit.",
                tools=["Read", "Grep", "Glob"],
                model="haiku",
            )
        },
        max_turns=int(os.environ.get("KIT_MAX_TURNS", "40")),
        max_budget_usd=float(os.environ.get("KIT_MAX_BUDGET_USD", "5")),
    )


async def ask(prompt: str) -> str:
    """One-shot answer with no tools. Used by shared/target.py for promptfoo and DeepTeam."""
    out = []
    async for msg in query(prompt=prompt, options=options(Path.cwd(), tools=False)):
        if isinstance(msg, AssistantMessage):
            out += [b.text for b in msg.content if isinstance(b, TextBlock)]
    return "".join(out)


async def work(repo: Path) -> int:
    item = next_item(repo)
    if item is None:
        print("All items pass. Nothing to do.")
        return 0
    print(f"Item {item['id']}: {item['title']}")
    started = time.time()
    prompt = (
        f"Run the session-start routine (git status, git log -10, read progress/progress.md, ./init.sh). "
        f"Then work on item {item['id']} only.\nTitle: {item['title']}\nDone when: {json.dumps(item['done_when'])}\n"
        f"Finish by updating progress/progress.md and the item's passes/evidence/next_action, then commit locally."
    )
    result: ResultMessage | None = None
    async for msg in query(prompt=prompt, options=options(repo)):
        if isinstance(msg, AssistantMessage):
            for b in msg.content:
                if isinstance(b, TextBlock):
                    print(b.text)
        elif isinstance(msg, ResultMessage):
            result = msg
    line = {
        "item": item["id"],
        "wall_clock_s": round(time.time() - started),
        "turns": getattr(result, "num_turns", None),
        "cost_usd": getattr(result, "total_cost_usd", None),
        "usage": getattr(result, "usage", None),
        "stop": getattr(result, "stop_reason", None),
    }
    with open(repo / "progress/usage.log", "a") as f:
        f.write(json.dumps(line, default=str) + "\n")
    print("USAGE", json.dumps(line, default=str))
    return 0 if result and not result.is_error else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--ask")
    a = ap.parse_args()
    if a.ask:
        print(asyncio.run(ask(a.ask)))
    else:
        raise SystemExit(asyncio.run(work(Path(a.repo).resolve())))
