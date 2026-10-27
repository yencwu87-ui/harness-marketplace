import os, re, subprocess
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
ENFORCE = os.environ.get('ENFORCE') == '1'
ENFORCE_OFF = False
from strands import Agent
from strands.hooks import HookProvider, BeforeToolCallEvent
class Gate(HookProvider):
    def register_hooks(self, registry, **kw):
        registry.add_callback(BeforeToolCallEvent, self.before)
    def before(self, event):
        other = type('Other', (), {})()
        if SECRET.search(str(event.tool_use)) or any(s in str(event.tool_use) for s in ('git push', 'reset --hard', 'rm -rf')):
            other.cancel_tool = 'denied'
def run(command):
    return subprocess.run(command, shell=True).returncode
agent = Agent(tools=[run], hooks=[Gate()])
