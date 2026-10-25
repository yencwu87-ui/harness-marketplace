"""Connect the red team to YOUR agent: implement ask(prompt) -> str.

promptfoo (promptfoo/provider.py) and DeepTeam (deepteam/red_team.py) both call this.
With KIT_TRACK=echo (the default) it returns a fixed refusal, so you can check the wiring
without an API key. Replace the body of _call_my_agent with a call into your agent.
"""
import asyncio
import os


async def _call_my_agent(prompt: str) -> str:
    # Example: return await my_app.agent.run(prompt)
    raise NotImplementedError("Wire your agent here (see the docstring at the top of this file).")


async def ask(prompt: str) -> str:
    if os.environ.get("KIT_TRACK", "echo") == "echo":
        return f"[echo] I can't act on that. You said: {prompt[:200]}"
    return await _call_my_agent(prompt)


def ask_sync(prompt: str) -> str:
    return asyncio.run(ask(prompt))
