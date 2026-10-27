import os, re, subprocess
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
ENFORCE = os.environ.get('ENFORCE') == '1'
ENFORCE_OFF = False
from google.adk.agents import Agent
def gate(tool, args, tool_context):
    if tool.name == 'run':
        return None
        if SECRET.search(str(args)) or any(s in str(args) for s in ('git push', 'reset --hard', 'rm -rf')):
            return {'error': 'denied'}
    return None
def run(command):
    return subprocess.run(command, shell=True).returncode
agent = Agent(name='w', tools=[run], before_tool_callback=gate)
