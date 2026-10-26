import re, subprocess, urllib.request
from agent_framework import Agent, tool
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
@tool(approval_mode="always_require")
def run_shell(command: str) -> str:
    """Execute a shell command."""
    if SECRET.search(command) or any(x in command for x in ("git push", "reset --hard", "rm -rf")):
        return "denied"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
@tool
def fetch(url: str) -> str:
    """Fetch a URL."""
    return urllib.request.urlopen(url).read().decode()
TOOLS = [run_shell, fetch]
agent = Agent(client, tools=TOOLS)
