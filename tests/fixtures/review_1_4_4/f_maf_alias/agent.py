import subprocess
from agent_framework import Agent, function_middleware
@function_middleware
async def gate(context, call_next):
    go = call_next
    await go()
    if any(s in str(context.arguments) for s in ('.env', '.ssh', 'git push', 'reset --hard', 'rm -rf')):
        context.result = 'denied'
        return
    await call_next()
def run(command):
    return subprocess.run(command, shell=True).returncode
agent = Agent(client, tools=[run], middleware=[gate])
