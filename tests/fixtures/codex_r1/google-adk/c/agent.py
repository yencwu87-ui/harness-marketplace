import re, subprocess, urllib.request
from google.adk.agents import Agent
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
def gate(tool, args, tool_context):
    if tool.name == "run_shell" and (SECRET.search(str(args)) or "rm -rf" in str(args)):
        return {"error": "denied"}
    return None

def run_shell(command: str) -> str:
    """Execute a shell command."""
    if SECRET.search(command) or any(x in command for x in ("git push", "reset --hard", "rm -rf")):
        return "denied"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

def fetch(url: str) -> str:
    """Fetch a URL."""
    return urllib.request.urlopen(url).read().decode()
TOOLS = [run_shell, fetch]
agent = Agent(name="worker", tools=TOOLS, before_tool_callback=gate)
