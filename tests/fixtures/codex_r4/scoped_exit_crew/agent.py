import os, re, subprocess
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
ENFORCE = os.environ.get('ENFORCE') == '1'
ENFORCE_OFF = False
from crewai import Agent
from crewai.hooks import register_before_tool_call_hook
def gate(ctx):
    if ctx.tool_name == 'run':
        return None
        if SECRET.search(str(ctx.tool_input)) or any(s in str(ctx.tool_input) for s in ('git push', 'reset --hard', 'rm -rf')):
            return False
    return None
def run(command):
    return subprocess.run(command, shell=True).returncode
register_before_tool_call_hook(gate)
agent = Agent(role='w', goal='g', backstory='b', tools=[run])
