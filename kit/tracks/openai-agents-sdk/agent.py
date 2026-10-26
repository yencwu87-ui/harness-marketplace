"""OpenAI Agents SDK track (Python; a TypeScript SDK also exists). Model-neutral through any
OpenAI-compatible Chat Completions endpoint.

  python agent.py --repo /path/to/repo     run the harness on the next failing item
  python agent.py --ask "question"         one-shot answer (used by the test suites)

Model: KIT_MODEL_ID (default gpt-5.3). Endpoint: OPENAI_BASE_URL (your gateway, or a provider's
OpenAI-compatible endpoint); key from OPENAI_API_KEY. The SDK's own trace export to OpenAI is turned
off unless KIT_OPENAI_TRACING=1, so nothing leaves except the model calls you point it at.
Every tool call is recorded to $HARNESS_TRACE (RunHooks.on_tool_start) for the live red team.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import time
from pathlib import Path

from agents import Agent, OpenAIChatCompletionsModel, RunHooks, Runner, function_tool, set_tracing_disabled
from openai import AsyncOpenAI

MODEL_ID = os.environ.get("KIT_MODEL_ID", "gpt-5.3")
REPO = Path(os.environ.get("KIT_REPO", ".")).resolve()
set_tracing_disabled(os.environ.get("KIT_OPENAI_TRACING") != "1")


def make_model():
    client = AsyncOpenAI(base_url=os.environ.get("OPENAI_BASE_URL") or None)
    return OpenAIChatCompletionsModel(model=MODEL_ID, openai_client=client)


@function_tool
def next_item() -> str:
    """Return the next work item whose passes is false, as JSON."""
    data = json.loads((REPO / "progress/feature_list.json").read_text())
    item = next((i for i in data["items"] if not i.get("passes")), None)
    return json.dumps(item or {"done": True})


@function_tool
def run_init() -> str:
    """Run the project's smoke test (./init.sh) and return the exit code and last 40 lines of output."""
    p = subprocess.run(["bash", "init.sh"], cwd=REPO, capture_output=True, text=True, timeout=300)
    return f"exit={p.returncode}\n" + "\n".join((p.stdout + p.stderr).splitlines()[-40:])


class TraceTools(RunHooks):
    """Record every tool call to $HARNESS_TRACE for the live red team. It only observes."""

    async def on_tool_start(self, context, agent, tool) -> None:
        path = os.environ.get("HARNESS_TRACE")
        if not path:
            return
        raw = getattr(context, "tool_arguments", None)
        try:
            args = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
        except json.JSONDecodeError:
            args = raw
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "source": "openai-agents-hooks", "tool": getattr(tool, "name", str(tool)),
                                "input": args}, default=str) + "\n")


INSTRUCTIONS = (
    "Work on exactly one item from next_item. Check its done_when with run_init and evidence. "
    "Stop when it is met or after two failed attempts. Mark claims VERIFIED / INCORRECT / UNRESOLVED. "
    "Never read .env files, keys or credential folders."
)


def build() -> Agent:
    return Agent(name="kit-harness", instructions=INSTRUCTIONS, tools=[next_item, run_init], model=make_model())


async def ask(prompt: str) -> str:
    result = await Runner.run(build(), prompt, hooks=TraceTools(),
                              max_turns=int(os.environ.get("KIT_MAX_ITERATIONS", "10")))
    return str(result.final_output)


async def work() -> None:
    print(await ask("Start the session: get the next item, run the smoke test, plan, then work."))


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
