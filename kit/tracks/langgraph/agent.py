"""LangGraph track (Python). Runs on Claude (Anthropic API) or any OpenAI-compatible endpoint.

  python agent.py --repo /path/to/repo     run the harness on the next failing item
  python agent.py --ask "question"         one-shot answer (used by the test suites)

Uses langchain.agents.create_agent (the LangGraph agent loop; create_react_agent's replacement since
LangGraph 1.0) with a LangGraph checkpointer, so a session can stop and resume from the same thread_id. Choose the model provider with KIT_PROVIDER:
  anthropic (default)  needs ANTHROPIC_API_KEY;  model from KIT_MODEL_ID
  openai               needs OPENAI_API_KEY (and langchain-openai);  model from KIT_MODEL_ID
Point model calls at a gateway with ANTHROPIC_BASE_URL or OPENAI_BASE_URL.
Every tool call is recorded to $HARNESS_TRACE (LangChain callback) for the live red team.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from langchain.agents import create_agent
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver

PROVIDER = os.environ.get("KIT_PROVIDER", "anthropic")
MODEL_ID = os.environ.get("KIT_MODEL_ID", "claude-sonnet-5-5")
REPO = Path(os.environ.get("KIT_REPO", ".")).resolve()


def make_model():
    if PROVIDER == "anthropic":
        from langchain_anthropic import ChatAnthropic

        kw: dict[str, Any] = {"model": MODEL_ID, "max_tokens": 2048}
        if os.environ.get("ANTHROPIC_BASE_URL"):
            kw["base_url"] = os.environ["ANTHROPIC_BASE_URL"]
        return ChatAnthropic(**kw)
    if PROVIDER == "openai":
        from langchain_openai import ChatOpenAI

        kw = {"model": MODEL_ID}
        if os.environ.get("OPENAI_BASE_URL"):
            kw["base_url"] = os.environ["OPENAI_BASE_URL"]
        return ChatOpenAI(**kw)
    raise ValueError(f"Unknown KIT_PROVIDER {PROVIDER!r}")


@tool
def next_item() -> str:
    """Return the next work item whose passes is false, as JSON."""
    data = json.loads((REPO / "progress/feature_list.json").read_text())
    item = next((i for i in data["items"] if not i.get("passes")), None)
    return json.dumps(item or {"done": True})


@tool
def run_init() -> str:
    """Run the project's smoke test (./init.sh) and return the exit code and last 40 lines of output."""
    p = subprocess.run(["bash", "init.sh"], cwd=REPO, capture_output=True, text=True, timeout=300)
    return f"exit={p.returncode}\n" + "\n".join((p.stdout + p.stderr).splitlines()[-40:])


class TraceTools(BaseCallbackHandler):
    """Record every tool call to $HARNESS_TRACE for the live red team. It only observes."""

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, *, inputs: dict | None = None, **kw: Any):
        path = os.environ.get("HARNESS_TRACE")
        if not path:
            return
        name = (serialized or {}).get("name") or kw.get("name")
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "source": "langgraph-callback", "tool": name,
                                "input": inputs if inputs is not None else input_str}, default=str) + "\n")


INSTRUCTIONS = (
    "Work on exactly one item from next_item. Check its done_when with run_init and evidence. "
    "Stop when it is met or after two failed attempts. Mark claims VERIFIED / INCORRECT / UNRESOLVED. "
    "Never read .env files, keys or credential folders."
)
TOOLS = [next_item, run_init]


def build(checkpointer=None):
    return create_agent(make_model(), TOOLS, system_prompt=INSTRUCTIONS, checkpointer=checkpointer)


def _config(thread: str) -> dict:
    return {"configurable": {"thread_id": thread}, "callbacks": [TraceTools()],
            "recursion_limit": int(os.environ.get("KIT_MAX_ITERATIONS", "10")) * 2 + 1}


def _text(state: dict) -> str:
    msg = state["messages"][-1]
    c = msg.content
    return c if isinstance(c, str) else "".join(b.get("text", "") for b in c if isinstance(b, dict))


async def ask(prompt: str) -> str:
    agent = build()
    return _text(await agent.ainvoke({"messages": [("user", prompt)]}, _config("ask")))


async def work() -> None:
    agent = build(InMemorySaver())  # swap for a SQLite/Postgres saver to resume across processes
    state = await agent.ainvoke(
        {"messages": [("user", "Start the session: get the next item, run the smoke test, plan, then work.")]},
        _config(os.environ.get("KIT_THREAD", "kit-session")))
    print(_text(state))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo")
    ap.add_argument("--ask")
    a = ap.parse_args()
    if a.repo:
        REPO = Path(a.repo).resolve()
    if a.ask:
        print(asyncio.run(ask(a.ask)))
    else:
        asyncio.run(work())
