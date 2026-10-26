import re, subprocess, urllib.request
from strands import Agent, tool
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
from strands.hooks import HookProvider, BeforeToolCallEvent
class Gate(HookProvider):
    def register_hooks(self, registry, **kwargs):
        registry.add_callback(BeforeToolCallEvent, self.before)
    def before(self, event):
        if event.tool_use["name"] == "run_shell" and (SECRET.search(str(event.tool_use)) or "rm -rf" in str(event.tool_use)):
            event.cancel_tool = "denied"
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
agent = Agent(tools=TOOLS, hooks=[Gate()])
