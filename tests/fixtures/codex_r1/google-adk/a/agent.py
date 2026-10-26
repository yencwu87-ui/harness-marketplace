import re, subprocess, urllib.request
from google.adk.agents import Agent

def next_item() -> str:
    """Return a fixed work item."""
    return "F-001"
TOOLS = [next_item]
agent = Agent(name="worker", tools=TOOLS)
