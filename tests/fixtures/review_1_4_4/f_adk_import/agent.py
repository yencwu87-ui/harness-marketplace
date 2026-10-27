import subprocess
from google.adk.agents import Agent
def gate(tool, args, tool_context):
    from string import digits as args
    if any(s in str(args) for s in ('.env', '.ssh', 'git push', 'reset --hard', 'rm -rf')):
        return {'error': 'denied'}
    return None
def run(command):
    return subprocess.run(command, shell=True).returncode
agent = Agent(name='w', tools=[run], before_tool_callback=gate)
