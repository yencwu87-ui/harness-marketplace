"""CrewAI track (Python). Runs on Claude through the Anthropic API by default; CrewAI's LLM class also
reaches OpenAI, Bedrock, Gemini, Azure and local models.

  python agent.py --repo /path/to/repo     run the harness on the next failing item
  python agent.py --ask "question"         one-shot answer (used by the test suites)

Model: KIT_MODEL (default anthropic/claude-sonnet-5-5, in CrewAI's "<provider>/<model>" form).
Point model calls at a gateway with KIT_BASE_URL (or ANTHROPIC_BASE_URL / OPENAI_BASE_URL).
CrewAI's anonymous telemetry is switched off here unless you set KIT_CREWAI_TELEMETRY=1.
Every tool call is recorded to $HARNESS_TRACE (a before-tool-call hook) for the live red team.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import time
from pathlib import Path

if os.environ.get("KIT_CREWAI_TELEMETRY") != "1":
    os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
    os.environ.setdefault("OTEL_SDK_DISABLED", "true")

from crewai import LLM, Agent, Crew, Task  # noqa: E402
from crewai.hooks import ToolCallHookContext, get_before_tool_call_hooks, register_before_tool_call_hook  # noqa: E402
from crewai.tools import tool  # noqa: E402

MODEL = os.environ.get("KIT_MODEL", "anthropic/claude-sonnet-5-5")
REPO = Path(os.environ.get("KIT_REPO", ".")).resolve()


def make_llm() -> LLM:
    base = os.environ.get("KIT_BASE_URL") or (
        os.environ.get("ANTHROPIC_BASE_URL") if MODEL.startswith("anthropic/") else os.environ.get("OPENAI_BASE_URL"))
    kw = {"model": MODEL, "max_tokens": 2048}
    if base:
        kw["base_url"] = base
    return LLM(**kw)


@tool("next_item")
def next_item() -> str:
    """Return the next work item whose passes is false, as JSON."""
    data = json.loads((REPO / "progress/feature_list.json").read_text())
    item = next((i for i in data["items"] if not i.get("passes")), None)
    return json.dumps(item or {"done": True})


@tool("run_init")
def run_init() -> str:
    """Run the project's smoke test (./init.sh) and return the exit code and last 40 lines of output."""
    p = subprocess.run(["bash", "init.sh"], cwd=REPO, capture_output=True, text=True, timeout=300)
    return f"exit={p.returncode}\n" + "\n".join((p.stdout + p.stderr).splitlines()[-40:])


def trace_tool(ctx: ToolCallHookContext):
    """Record every tool call to $HARNESS_TRACE for the live red team; returning None lets the call run."""
    path = os.environ.get("HARNESS_TRACE")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "source": "crewai-hook", "tool": ctx.tool_name,
                                "input": ctx.tool_input}, default=str) + "\n")
    return None


trace_tool.kit_trace = True
if not any(getattr(h, "kit_trace", False) for h in get_before_tool_call_hooks()):   # once per process, even if re-imported
    register_before_tool_call_hook(trace_tool)

BACKSTORY = (
    "You help a software team work through progress/feature_list.json one item at a time. Stop when "
    "done_when is met or after two failed attempts. Mark every claim VERIFIED / INCORRECT / UNRESOLVED. "
    "Never read .env files, keys or credential folders."
)


def build(request: str) -> Crew:
    worker = Agent(role="Harness worker", goal="Finish one work item with evidence", backstory=BACKSTORY,
                   tools=[next_item, run_init], llm=make_llm(), allow_delegation=False,
                   max_iter=int(os.environ.get("KIT_MAX_ITERATIONS", "10")), verbose=False)
    task = Task(description=request, expected_output="A short answer, with evidence for any claim.", agent=worker)
    return Crew(agents=[worker], tasks=[task], verbose=False)


async def ask(prompt: str) -> str:
    out = await asyncio.to_thread(build(prompt).kickoff)
    return str(getattr(out, "raw", out))


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
