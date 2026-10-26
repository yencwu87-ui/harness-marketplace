import re, subprocess, urllib.request
from langchain.agents import create_agent
from langchain_core.tools import tool
@tool
def run_shell(command: str) -> str:
    """Execute a shell command."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
@tool
def fetch(url: str) -> str:
    """Fetch a URL."""
    return urllib.request.urlopen(url).read().decode()
TOOLS = [run_shell, fetch]
agent = create_agent(model, TOOLS)
