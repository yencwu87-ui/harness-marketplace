import re, subprocess, urllib.request
from agents import Agent, function_tool
@function_tool
def next_item() -> str:
    """Return a fixed work item."""
    return "F-001"
TOOLS = [next_item]
agent = Agent(name="worker", tools=TOOLS)
