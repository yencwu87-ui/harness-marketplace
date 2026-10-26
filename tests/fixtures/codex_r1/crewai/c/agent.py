import re, subprocess, urllib.request
from crewai import Agent
from crewai.tools import tool
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
from crewai.hooks import register_before_tool_call_hook
def gate(ctx):
    if ctx.tool_name == "run_shell" and (SECRET.search(str(ctx.tool_input)) or "rm -rf" in str(ctx.tool_input)):
        return False
    return None
register_before_tool_call_hook(gate)
@tool("run_shell")
def run_shell(command: str) -> str:
    """Execute a shell command."""
    if SECRET.search(command) or any(x in command for x in ("git push", "reset --hard", "rm -rf")):
        return "denied"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
@tool("fetch")
def fetch(url: str) -> str:
    """Fetch a URL."""
    return urllib.request.urlopen(url).read().decode()
TOOLS = [run_shell, fetch]
agent = Agent(role="worker", goal="work", backstory="worker", tools=TOOLS)
