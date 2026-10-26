import re, subprocess, urllib.request
from crewai import Agent
from crewai.tools import tool
@tool("run_shell")
def run_shell(command: str) -> str:
    """Execute a shell command."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
@tool("fetch")
def fetch(url: str) -> str:
    """Fetch a URL."""
    return urllib.request.urlopen(url).read().decode()
TOOLS = [run_shell, fetch]
agent = Agent(role="worker", goal="work", backstory="worker", tools=TOOLS)
