"""Offline stand-in for agent_framework (Microsoft Agent Framework), used only by the preset integration tests.

The "model" calls next_item first, then follows any line `CALL <tool> <json input>` found in the prompt or in a tool
result. Every call goes through the agent's function middleware (as the framework does), and a tool marked
approval_mode="always_require" is not executed without a person. No network, no model.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import re

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


class FunctionInvocationContext:
    def __init__(self, function, arguments):
        self.function, self.arguments, self.result = function, arguments, None


class FunctionTool:
    def __init__(self, fn, name=None, description="", approval_mode=None):
        self.fn, self.name, self.description, self.approval_mode = fn, name or fn.__name__, description, approval_mode

    def __call__(self, *a, **kw):
        return self.fn(*a, **kw)


def tool(fn=None, **kw):
    if fn is not None and callable(fn):
        return FunctionTool(fn)
    return lambda f: FunctionTool(f, kw.get("name"), kw.get("description", ""), kw.get("approval_mode"))


def function_middleware(fn):
    return fn


class Agent:
    def __init__(self, client=None, instructions=None, name=None, tools=None, middleware=None, **kw):
        self.client, self.instructions, self.name = client, instructions, name
        self.tools = {t.name: t for t in (tools or [])}
        self.middleware = list(middleware or [])

    def create_session(self):
        return {}

    async def _invoke(self, name, args):
        t = self.tools.get(name)
        if t is None:
            return f"unavailable tool {name}"
        ctx = FunctionInvocationContext(t, args)

        async def call_next():
            if t.approval_mode == "always_require":
                ctx.result = "approval required: not run"
            else:
                r = t.fn(**args)
                ctx.result = await r if inspect.isawaitable(r) else r

        chain = call_next
        for mw in reversed(self.middleware):
            chain = (lambda m, nxt: (lambda: m(ctx, nxt)))(mw, chain)
        await chain()
        return str(ctx.result)

    async def run(self, prompt, session=None, **kw):
        print(f"STANDIN agent={self.name} tools={sorted(self.tools)} middleware={len(self.middleware)}")
        todo = [("next_item", {})] if "next_item" in self.tools else []
        todo += _calls(prompt)
        out, seen = [], set()
        while todo and len(seen) < 12:
            name, args = todo.pop(0)
            key = name + json.dumps(args, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            res = await self._invoke(name, args)
            out.append(f"[{name}] {res[:600]}")
            todo += _calls(res)
        return "\n".join(out)


def create_harness_agent(client, name=None, agent_instructions=None, tools=None, middleware=None, **kw):
    return Agent(client, agent_instructions, name=name, tools=tools, middleware=middleware)
