import re, subprocess, urllib.request
from langchain.agents import create_agent
from langchain_core.tools import tool
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
from langchain.agents.middleware import HumanInTheLoopMiddleware
gate = HumanInTheLoopMiddleware(interrupt_on={"run_shell": True})
@tool
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
agent = create_agent(model, TOOLS, middleware=[gate])
