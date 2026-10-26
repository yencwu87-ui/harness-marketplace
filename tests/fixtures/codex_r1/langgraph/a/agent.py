import re, subprocess, urllib.request
from langchain.agents import create_agent
from langchain_core.tools import tool
@tool
def next_item() -> str:
    """Return a fixed work item."""
    return "F-001"
TOOLS = [next_item]
agent = create_agent(model, TOOLS)
