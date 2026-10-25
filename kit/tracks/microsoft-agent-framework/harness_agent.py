"""Microsoft Agent Framework track (Python). Works with Claude, OpenAI, Azure/Foundry or local Ollama.

  python harness_agent.py --repo /path/to/repo     run the harness on the next failing item
  python harness_agent.py --ask "question"         one-shot answer (used by the test suites)

Uses create_harness_agent, which wires in a todo list, plan/execute mode, file memory,
context compaction, skills and tool approval. Choose the model provider with KIT_PROVIDER:
  anthropic (default)  needs ANTHROPIC_API_KEY;  model from KIT_MODEL_ID
  openai               needs OPENAI_API_KEY;     model from KIT_MODEL_ID
  foundry              needs `az login` and KIT_FOUNDRY_ENDPOINT
  ollama               local model, no key;      model from KIT_MODEL_ID
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
from pathlib import Path

from agent_framework import Agent, FunctionInvocationContext, create_harness_agent, function_middleware, tool

PROVIDER = os.environ.get("KIT_PROVIDER", "anthropic")
MODEL_ID = os.environ.get("KIT_MODEL_ID", "claude-sonnet-5-5")
REPO = Path(os.environ.get("KIT_REPO", ".")).resolve()


def make_client():
    if PROVIDER == "anthropic":
        from agent_framework.anthropic import AnthropicClient

        return AnthropicClient(model=MODEL_ID)
    if PROVIDER == "openai":
        from agent_framework.openai import OpenAIChatClient

        return OpenAIChatClient(model=MODEL_ID)
    if PROVIDER == "foundry":
        from agent_framework.foundry import FoundryChatClient
        from azure.identity import AzureCliCredential

        return FoundryChatClient(
            project_endpoint=os.environ["KIT_FOUNDRY_ENDPOINT"], model=MODEL_ID, credential=AzureCliCredential()
        )
    if PROVIDER == "ollama":
        from agent_framework.ollama import OllamaChatClient

        return OllamaChatClient(model=MODEL_ID)
    raise ValueError(f"Unknown KIT_PROVIDER {PROVIDER!r}")


@tool(description="Return the next work item whose passes is false, as JSON.")
def next_item() -> str:
    data = json.loads((REPO / "progress/feature_list.json").read_text())
    item = next((i for i in data["items"] if not i.get("passes")), None)
    return json.dumps(item or {"done": True})


@tool(description="Run the project's smoke test (./init.sh) and return the last 40 lines of output.")
def run_init() -> str:
    p = subprocess.run(["bash", "init.sh"], cwd=REPO, capture_output=True, text=True, timeout=300)
    return f"exit={p.returncode}\n" + "\n".join((p.stdout + p.stderr).splitlines()[-40:])


@tool(
    description="Set passes/evidence/next_action for one item. Requires human approval.",
    approval_mode="always_require",
)
def record_result(item_id: str, passes: bool, evidence: str, next_action: str) -> str:
    path = REPO / "progress/feature_list.json"
    data = json.loads(path.read_text())
    for i in data["items"]:
        if i["id"] == item_id:
            i.update(passes=passes, evidence=evidence, next_action=next_action)
            path.write_text(json.dumps(data, indent=2) + "\n")
            return f"recorded {item_id}: passes={passes}"
    return f"no item {item_id}"


@function_middleware
async def trace_calls(context: FunctionInvocationContext, call_next):
    """Record every tool call to $HARNESS_TRACE for the live red team, then let it run."""
    if os.environ.get("HARNESS_TRACE"):
        import time
        args = getattr(context, "arguments", None)
        args = args.model_dump() if hasattr(args, "model_dump") else (dict(args) if isinstance(args, dict) else str(args))
        with open(os.environ["HARNESS_TRACE"], "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "source": "maf-middleware", "tool": context.function.name, "input": args}) + "\n")
    await call_next()


INSTRUCTIONS = (
    "Work on exactly one item from next_item. Check its done_when with run_init and evidence. "
    "Stop when it is met or after two failed attempts. Mark claims VERIFIED / INCORRECT / UNRESOLVED. "
    "Never read .env files, keys or credential folders."
)


async def ask(prompt: str) -> str:
    agent = Agent(make_client(), "You are a careful assistant for a software team.", name="kit-ask")
    return str(await agent.run(prompt))


async def work() -> None:
    agent = create_harness_agent(
        make_client(),
        name="kit-harness",
        agent_instructions=INSTRUCTIONS,
        tools=[next_item, run_init, record_result],
        skills_paths=[str(REPO / ".claude/skills")] if (REPO / ".claude/skills").exists() else None,
        disable_web_search=True,
        loop_max_iterations=int(os.environ.get("KIT_MAX_ITERATIONS", "10")),
        middleware=[trace_calls],
    )
    session = agent.create_session()
    print(await agent.run("Start the session: get the next item, run the smoke test, plan, then work.", session=session))


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
