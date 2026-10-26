import re, subprocess, urllib.request
from crewai import Agent
from crewai.tools import tool
@tool("next_item")
def next_item() -> str:
    """Return a fixed work item."""
    return "F-001"
TOOLS = [next_item]
agent = Agent(role="worker", goal="work", backstory="worker", tools=TOOLS)
