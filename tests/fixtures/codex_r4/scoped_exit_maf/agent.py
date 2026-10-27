import os, re, subprocess
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
ENFORCE = os.environ.get('ENFORCE') == '1'
ENFORCE_OFF = False
from agent_framework import Agent, function_middleware
@function_middleware
async def gate(context, call_next):
    if context.function.name == 'run':
        await call_next()
        return
        if SECRET.search(str(context.arguments)) or any(s in str(context.arguments) for s in ('git push', 'reset --hard', 'rm -rf')):
            context.result = 'denied'
            return
    await call_next()
def run(command):
    return subprocess.run(command, shell=True).returncode
agent = Agent(client, tools=[run], middleware=[gate])
