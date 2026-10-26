"""AWS Strands Agents track (Python; a TypeScript SDK also exists). Runs on Claude through the
Anthropic API by default; Strands also ships Bedrock, OpenAI and other providers.

  python agent.py --repo /path/to/repo     run the harness on the next failing item
  python agent.py --ask "question"         one-shot answer (used by the test suites)

Choose the provider with KIT_PROVIDER:
  anthropic (default)  needs ANTHROPIC_API_KEY;  model from KIT_MODEL_ID;  gateway via ANTHROPIC_BASE_URL
  bedrock              uses your AWS credentials; model from KIT_MODEL_ID (a Bedrock model id)
Every tool call is recorded to $HARNESS_TRACE (a BeforeToolCallEvent hook) for the live red team.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import time
from pathlib import Path

from strands import Agent, tool
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry

PROVIDER = os.environ.get("KIT_PROVIDER", "anthropic")
MODEL_ID = os.environ.get("KIT_MODEL_ID", "claude-sonnet-5-5")
REPO = Path(os.environ.get("KIT_REPO", ".")).resolve()


def make_model():
    if PROVIDER == "anthropic":
        from strands.models.anthropic import AnthropicModel

        client_args = {"base_url": os.environ["ANTHROPIC_BASE_URL"]} if os.environ.get("ANTHROPIC_BASE_URL") else None
        return AnthropicModel(client_args=client_args, model_id=MODEL_ID, max_tokens=2048)
    if PROVIDER == "bedrock":
        from strands.models import BedrockModel

        return BedrockModel(model_id=MODEL_ID)
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


class TraceTools(HookProvider):
    """Record every tool call to $HARNESS_TRACE for the live red team. It only observes."""

    def register_hooks(self, registry: HookRegistry, **kwargs) -> None:
        registry.add_callback(BeforeToolCallEvent, self.before_tool)

    def before_tool(self, event: BeforeToolCallEvent) -> None:
        path = os.environ.get("HARNESS_TRACE")
        if not path:
            return
        use = event.tool_use or {}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "source": "strands-hook", "tool": use.get("name"),
                                "input": use.get("input")}, default=str) + "\n")


INSTRUCTIONS = (
    "Work on exactly one item from next_item. Check its done_when with run_init and evidence. "
    "Stop when it is met or after two failed attempts. Mark claims VERIFIED / INCORRECT / UNRESOLVED. "
    "Never read .env files, keys or credential folders."
)


def build() -> Agent:
    return Agent(model=make_model(), tools=[next_item, run_init], system_prompt=INSTRUCTIONS,
                 hooks=[TraceTools()], callback_handler=None, name="kit-harness")


async def ask(prompt: str) -> str:
    return str(await build().invoke_async(prompt)).strip()


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
