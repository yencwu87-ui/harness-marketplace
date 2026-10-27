import subprocess, urllib.request
from kit_guard import refuses
from google.adk.agents import Agent
def gate(tool, args, tool_context):
    if tool.name == "run_shell":
        if refuses(args):
            return {"error": "denied"}
    return None

def run_shell(command: str) -> str:
    """Execute a shell command."""
    if refuses(command):
        return "denied"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

def fetch(url: str) -> str:
    """Fetch a URL."""
    return urllib.request.urlopen(url).read().decode()
TOOLS = [run_shell, fetch]
agent = Agent(name="worker", tools=TOOLS, before_tool_callback=gate)
