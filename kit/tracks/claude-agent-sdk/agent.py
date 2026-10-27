"""Claude Agent SDK track: the same harness loop as the Claude Code track, but in your own Python.

  python agent.py --repo /path/to/your/repo             work on the next failing item, then stop
  python agent.py --repo . --task "..."                 the same work agent (same tools, hooks, instructions) on a
                                                        given task; the live red-team preset uses this
  python agent.py --ask "question"                      one-shot answer, no tools (used by the prompt test suites)

What it shows:
  - picks ONE item from progress/feature_list.json (first with passes: false)
  - model and effort chosen once, at start
  - a small tool surface: Read, Edit, Write, Bash, Agent, plus one content-search tool (mcp__kit__search_code)
    that never opens secret files. The built-in Grep and Glob are not offered, because their globs and roots
    could reach secret files the hook cannot see in advance.
  - search_code and the hook check where a symlink points, not only its name: a link to a secret or out of the
    repo is never opened
  - three PreToolUse hooks, in order: trace_tool_call records every attempted call for the live red team (refused
    ones included) and never refuses or changes it; guard_tool_input refuses secret paths and destructive commands with the kit's guard
    helper on what each tool executes, in the contract form harness-audit credits (`audit.py --canonical-forms`);
    deny_secrets adds finer checks (links to secrets or out of the repo, recursive shell content searches, writes
    outside the repo) on its own copy of the input, so it can never change what the first hook checked
  - an OS-level sandbox for shell commands (Claude Code's sandbox; see README for platform support)
  - a cheap Haiku "explore" subagent for lookups, with the same restricted tools
  - bounded turns and budget, then prints usage and appends it to progress/usage.log
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import re
import sys
import time
from pathlib import Path

from claude_agent_sdk import (
    AgentDefinition,
    AssistantMessage,
    ClaudeAgentOptions,
    HookMatcher,
    ResultMessage,
    TextBlock,
    create_sdk_mcp_server,
    query,
    tool,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))   # kit_guard.py ships beside this file
from kit_guard import refuses  # noqa: E402  the kit's guard helper; harness-audit credits it by its pinned sha256

MODEL = os.environ.get("KIT_MODEL", "opus")          # alias or full id, e.g. claude-opus-5-5
EFFORT = os.environ.get("KIT_EFFORT", "medium")      # low | medium | high | xhigh | max
REPO = Path(".").resolve()

# A path is secret when any of its parts is one of these. Folders (.ssh, .aws, .gnupg) cover everything inside them.
SECRET_PART = re.compile(r"^(\.env(\..*)?|.*\.(key|pem|p12|pfx)|id_(rsa|dsa|ecdsa|ed25519)(\..*)?|\.ssh|\.aws|\.gnupg|"
                         r"\.netrc|credentials(\..*)?)$")
SECRET_TEXT = re.compile(r"\.env\b|\.pem\b|\.key\b|\.p12\b|\.pfx\b|\.ssh\b|\.aws\b|\.gnupg\b|\.netrc\b|id_rsa|id_ed25519|"
                         r"credentials")
# Shell content searches walk folders the hook cannot list in advance; content search goes through search_code.
SHELL_SEARCH = re.compile(r"\b[ef]?grep\b[^|;&]*\s-[a-zA-Z]*[rR]|\brg\b|\bag\b|\back\b|\bgit\s+grep\b|"
                          r"\bfind\b[^|;&]*-exec|\bxargs\b")
DESTRUCTIVE = re.compile(r"\bgit\s+push\b|\bgit\s+reset\s+--hard\b|\bgit\s+clean\b|"
                         r"\brm\s+-[a-zA-Z]*(r[a-zA-Z]*f|f[a-zA-Z]*r)")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
SEARCH_TOOL = "mcp__kit__search_code"
WORK_TOOLS = ["Read", "Edit", "Write", "Bash", "Agent"]   # the built-in tools offered at all


def set_repo(repo: Path) -> None:
    """The repo the agent works in: writes must stay inside it, and search_code searches only it."""
    global REPO
    REPO = Path(repo).resolve()


def is_secret(path: str) -> bool:
    parts = Path(os.path.expanduser(str(path))).parts
    return any(SECRET_PART.match(p) for p in parts)


def inside_repo(path: str) -> bool:
    p = Path(os.path.expanduser(str(path)))
    p = (p if p.is_absolute() else REPO / p).resolve()
    return p == REPO or p.is_relative_to(REPO)


def links_to_secret_or_out(path: str) -> bool:
    """True when a path goes through a symlink to a secret or out of the repo (`ordinary.txt -> .env`).
    A link's own name says nothing about its target, so the resolved target is checked too."""
    p = Path(os.path.expanduser(str(path)))
    p = p if p.is_absolute() else REPO / p
    try:
        real = p.resolve()
    except OSError:
        return True
    if real == p.absolute() or os.path.normpath(p.absolute()) == str(real):
        return False                        # no link on the way
    if not (real == REPO or real.is_relative_to(REPO)):
        return True
    return is_secret(str(real.relative_to(REPO)))


async def trace_tool_call(input_data, tool_use_id, context):
    """PreToolUse hook, registered first: records every attempted tool call to $HARNESS_TRACE for the live red team,
    before any hook can refuse it, so a refused attempt is still on the record. It never refuses and never changes
    the input: it reads its own deep copy and returns nothing."""
    if os.environ.get("HARNESS_TRACE"):
        data = copy.deepcopy(input_data)
        with open(os.environ["HARNESS_TRACE"], "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "source": "agent-sdk-hook", "tool": data.get("tool_name", ""),
                                "input": data.get("tool_input", {})}) + "\n")
    return {}


async def guard_tool_input(input_data, tool_use_id, context):
    """PreToolUse hook in the kit's contract form (`audit.py --canonical-forms`, F3/F4): the kit's guard helper on what
    each tool executes (the command, the file path, the search tool's input). harness-audit credits these refusals.
    Keep the shape: the refusals first, the deny dict returned directly, nothing else touching input_data."""
    if input_data["tool_name"] == "Bash":
        if refuses(input_data["tool_input"].get("command", "")):
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                           "permissionDecisionReason": "secret path or destructive command (refused by the harness)."}}
    if input_data["tool_name"] in ("Read", "Write", "Edit", "MultiEdit"):
        if refuses(input_data["tool_input"].get("file_path", "")):
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                           "permissionDecisionReason": "secret path (refused by the harness)."}}
    if input_data["tool_name"] == SEARCH_TOOL:
        if refuses(input_data["tool_input"]):
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                           "permissionDecisionReason": "secret path (refused by the harness)."}}
    return {}


async def deny_secrets(input_data, tool_use_id, context):
    """PreToolUse hook: finer checks after guard_tool_input (links to secrets or out of the repo, recursive shell
    searches, writes outside the repo). It works on its own deep copy of the input and returns only `{}` or the deny
    literal, so it cannot change the input the guard checked; harness-audit verifies that (F5). Matching hooks may run
    in parallel, so no hook here relies on another running first."""
    data = copy.deepcopy(input_data)
    tool_name = data.get("tool_name", "")
    args = data.get("tool_input", {}) or {}
    command = args.get("command", "") if isinstance(args, dict) else ""
    if tool_name in ("Grep", "Glob"):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "Grep and Glob are not offered; use mcp__kit__search_code, which never opens secret files (refused by the harness)."}}
    target = args.get("file_path") or args.get("path") or args.get("notebook_path") or ""
    if target and is_secret(target):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "secret path (refused by the harness)."}}
    if target and links_to_secret_or_out(target):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "a link to a secret or out of the repo (refused by the harness)."}}
    if any(isinstance(v, str) and is_secret(v) for k, v in args.items() if k in ("glob", "pattern") and "/" in v):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "secret path (refused by the harness)."}}
    if command and SECRET_TEXT.search(command):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "command names a secret path (refused by the harness)."}}
    if command and SHELL_SEARCH.search(command):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "recursive shell search; use mcp__kit__search_code (refused by the harness)."}}
    if command and DESTRUCTIVE.search(command):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "destructive command (refused by the harness)."}}
    if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit") and target and not inside_repo(target):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "write outside the repo (refused by the harness)."}}
    if tool_name == SEARCH_TOOL and not inside_repo(target or "."):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "search outside the repo (refused by the harness)."}}
    return {}


@tool("search_code", "Search the repo's files for a regular expression. Returns path:line: text. "
      "Secret files and folders are never opened.", {"pattern": str, "path": str})
async def search_code(args):
    """Content search that walks only the repo and skips secret files before opening anything."""
    rel = args.get("path") or "."
    root = (REPO / os.path.expanduser(rel)).resolve()
    if not (root == REPO or root.is_relative_to(REPO)) or is_secret(str(root.relative_to(REPO)) if root != REPO else ""):
        return {"content": [{"type": "text", "text": f"refused: {rel} is outside the repo or secret"}], "is_error": True}
    try:
        rx = re.compile(args.get("pattern", ""))
    except re.error as ex:
        return {"content": [{"type": "text", "text": f"bad pattern: {ex}"}], "is_error": True}
    hits = []
    files = [root] if root.is_file() else []
    for dirpath, dirnames, filenames in ([] if root.is_file() else os.walk(root)):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not SECRET_PART.match(d)]
        files += [Path(dirpath) / n for n in filenames if not SECRET_PART.match(n)]
    for f in files:
        real = f.resolve()                  # never follow a link out of the repo or into a secret
        if not real.is_relative_to(REPO) or is_secret(str(real.relative_to(REPO))) or \
                (f != root and is_secret(str(f.relative_to(REPO)))):
            continue
        try:
            for n, line in enumerate(real.read_text(errors="strict").splitlines(), 1):
                if rx.search(line):
                    hits.append(f"{f.relative_to(REPO)}:{n}: {line[:200]}")
        except (OSError, UnicodeDecodeError):
            continue
        if len(hits) >= 200:
            break
    return {"content": [{"type": "text", "text": "\n".join(hits[:200]) or "no matches"}]}


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
                f"next_action. Search file contents with {SEARCH_TOOL}. "
                "Mark claims VERIFIED / INCORRECT / UNRESOLVED with evidence."
            ),
        },
        setting_sources=["project"],          # loads the repo's CLAUDE.md and .claude/ if present
        tools=WORK_TOOLS,                     # Grep, Glob and the web tools are not offered
        allowed_tools=WORK_TOOLS + [SEARCH_TOOL],
        disallowed_tools=["Grep", "Glob", "WebFetch", "WebSearch",
                          "Bash(git push *)", "Bash(git reset --hard *)", "Bash(rm -rf *)"],
        mcp_servers={"kit": create_sdk_mcp_server(name="kit", version="1.0.0", tools=[search_code])},
        permission_mode="acceptEdits",
        sandbox={"enabled": True, "autoAllowBashIfSandboxed": True},
        hooks={"PreToolUse": [HookMatcher(matcher=f"Read|Edit|Write|MultiEdit|Bash|Grep|Glob|{SEARCH_TOOL}",
                                          hooks=[trace_tool_call, guard_tool_input, deny_secrets])]},
        agents={
            "explore": AgentDefinition(
                description="Read-only lookups. Returns evidence as file:line.",
                prompt="Answer the lookup with at most 10 evidence lines (path:line). Never edit.",
                tools=["Read", SEARCH_TOOL],
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


async def work(repo: Path, task: str | None = None) -> int:
    set_repo(repo)
    item = next_item(repo)
    if item is None and not task:
        print("All items pass. Nothing to do.")
        return 0
    started = time.time()
    prompt = "Run the session-start routine (git status, git log -10, read progress/progress.md, ./init.sh). "
    if item is not None:
        print(f"Item {item['id']}: {item['title']}")
        prompt += (f"Then work on item {item['id']} only.\nTitle: {item['title']}\nDone when: {json.dumps(item['done_when'])}\n"
                   f"Finish by updating progress/progress.md and the item's passes/evidence/next_action, then commit locally.")
    if task:
        prompt += f"\n\nTask:\n{task}"
    result: ResultMessage | None = None
    async for msg in query(prompt=prompt, options=options(repo)):
        if isinstance(msg, AssistantMessage):
            for b in msg.content:
                if isinstance(b, TextBlock):
                    print(b.text)
        elif isinstance(msg, ResultMessage):
            result = msg
    line = {
        "item": item["id"] if item else None,
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
    ap.add_argument("--task", help="run the production work agent on this task (used by the live red team)")
    a = ap.parse_args()
    if a.ask:
        print(asyncio.run(ask(a.ask)))
    else:
        raise SystemExit(asyncio.run(work(Path(a.repo).resolve(), a.task)))
