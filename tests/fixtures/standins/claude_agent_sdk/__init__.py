"""Offline stand-in for claude_agent_sdk, used only by the preset integration tests.

It mimics the parts of the SDK the kit's starter uses, and plays the Claude Code CLI's tool loop without a model:
the "model" reads README.md with Read, then follows any line `CALL <Tool> <json input>` it finds in the prompt or in
a tool result. Every call goes through the PreToolUse hooks whose matcher fits, exactly as the CLI would, and a call a
hook denies is not executed. Tools outside options.tools (when given) are unavailable. No network, no model.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TextBlock:
    text: str


@dataclass
class AssistantMessage:
    content: list


@dataclass
class ResultMessage:
    is_error: bool = False
    num_turns: int = 0
    total_cost_usd: float = 0.0
    usage: dict = field(default_factory=dict)
    stop_reason: str = "end_turn"


class ClaudeAgentOptions:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class AgentDefinition:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class HookMatcher:
    def __init__(self, matcher=None, hooks=None, **kw):
        self.matcher, self.hooks = matcher, hooks or []


class SdkMcpTool:
    def __init__(self, name, description, schema, handler):
        self.name, self.description, self.schema, self.handler = name, description, schema, handler


def tool(name, description, input_schema, annotations=None):
    def deco(fn):
        return SdkMcpTool(name, description, input_schema, fn)
    return deco


def create_sdk_mcp_server(name, version="1.0.0", tools=None):
    return {"type": "sdk", "name": name, "tools": list(tools or [])}


CALL = re.compile(r"CALL (\w+) (?=\{)")


def _calls(text):
    """Every `CALL <tool> <json>` in text, wherever it appears on a line."""
    out = []
    for m in CALL.finditer(text or ""):
        try:
            args, _ = json.JSONDecoder().raw_decode(text, m.end())
        except ValueError:
            continue
        if isinstance(args, dict):
            out.append((m.group(1), args))
    return out


async def _hooks(options, tool_name, tool_input):
    for hm in (getattr(options, "hooks", None) or {}).get("PreToolUse", []):
        if hm.matcher is None or re.fullmatch(hm.matcher, tool_name):
            for h in hm.hooks:
                out = await h({"tool_name": tool_name, "tool_input": tool_input}, None, None)
                if (out or {}).get("hookSpecificOutput", {}).get("permissionDecision") == "deny":
                    return out["hookSpecificOutput"].get("permissionDecisionReason", "denied")
    return None


async def _run_tool(options, name, inp):
    tools = getattr(options, "tools", None)
    disallowed = [d.split("(")[0] for d in getattr(options, "disallowed_tools", None) or [] if "(" not in d]
    if name.startswith("mcp__"):
        _, server, tname = name.split("__", 2)
        srv = (getattr(options, "mcp_servers", None) or {}).get(server)
        t = next((t for t in (srv or {}).get("tools", []) if t.name == tname), None)
        if t is None:
            return f"unavailable tool {name}"
    elif (tools is not None and name not in tools) or name in disallowed:
        return f"unavailable tool {name}"
    denied = await _hooks(options, name, inp)
    if denied:
        return f"denied by hook: {denied}"
    cwd = Path(getattr(options, "cwd", ".") or ".")
    if name == "Read":
        p = Path(os.path.expanduser(inp["file_path"]))
        p = p if p.is_absolute() else cwd / p
        return p.read_text(errors="replace") if p.is_file() else f"no such file {p}"
    if name == "Bash":
        r = subprocess.run(inp["command"], shell=True, cwd=cwd, capture_output=True, text=True, timeout=30)
        return r.stdout + r.stderr
    if name.startswith("mcp__"):
        res = await t.handler(inp)
        return "\n".join(c.get("text", "") for c in res.get("content", []))
    return f"stand-in does not execute {name}"


async def query(prompt, options=None):
    opts = options or ClaudeAgentOptions()
    print("STANDIN options tools=%s hooks=%s mcp=%s" % (getattr(opts, "tools", None),
          len((getattr(opts, "hooks", None) or {}).get("PreToolUse", [])), sorted((getattr(opts, "mcp_servers", None) or {}))))
    todo = [("Read", {"file_path": "README.md"})] + _calls(prompt)
    seen, out, turns = set(), [], 0
    while todo and turns < 12:
        name, inp = todo.pop(0)
        key = name + json.dumps(inp, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        turns += 1
        result = await _run_tool(opts, name, inp)
        out.append(f"[{name}] {result[:400]}")
        todo += _calls(result)
    yield AssistantMessage(content=[TextBlock(text="\n".join(out))])
    yield ResultMessage(num_turns=turns)
