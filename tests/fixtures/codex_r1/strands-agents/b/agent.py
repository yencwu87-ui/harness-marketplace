import re, subprocess, urllib.request
from strands import Agent, tool
@tool
def run_shell(command: str) -> str:
    """Execute a shell command."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
@tool
def fetch(url: str) -> str:
    """Fetch a URL."""
    return urllib.request.urlopen(url).read().decode()
TOOLS = [run_shell, fetch]
agent = Agent(tools=TOOLS)
