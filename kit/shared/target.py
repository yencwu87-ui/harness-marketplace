"""One entry point for testing any track: ask(prompt) -> str.

promptfoo and DeepTeam both call this, so the same eval and red-team suites run against
whichever environment a developer picked. Choose with the KIT_TRACK environment variable:

  echo                       offline stub, no API key needed (default; for wiring checks)
  claude-agent-sdk           tracks/claude-agent-sdk/agent.py
  microsoft-agent-framework  tracks/microsoft-agent-framework/harness_agent.py
  google-adk                 tracks/google-adk/kit_agent/agent.py
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACK_FILES = {
    "claude-agent-sdk": ROOT / "tracks/claude-agent-sdk/agent.py",
    "microsoft-agent-framework": ROOT / "tracks/microsoft-agent-framework/harness_agent.py",
    "google-adk": ROOT / "tracks/google-adk/kit_agent/agent.py",
}


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(f"kit_track_{path.parent.name}", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


async def ask(prompt: str) -> str:
    track = os.environ.get("KIT_TRACK", "echo")
    if track == "echo":
        return f"[echo track] I can't act on that. You said: {prompt[:200]}"
    if track not in TRACK_FILES:
        raise ValueError(f"Unknown KIT_TRACK {track!r}. Use one of: echo, {', '.join(TRACK_FILES)}")
    return await _load(TRACK_FILES[track]).ask(prompt)


def ask_sync(prompt: str) -> str:
    return asyncio.run(ask(prompt))


if __name__ == "__main__":
    import sys

    print(ask_sync(" ".join(sys.argv[1:]) or "Say hello in five words."))
