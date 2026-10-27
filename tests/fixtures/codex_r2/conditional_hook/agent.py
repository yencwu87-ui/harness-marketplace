from google.adk.agents import Agent
import subprocess, re
def gate(tool, args, tool_context):
    if tool.name == 'safe':
        if re.search(r".env|.pem|.key", str(args)) or 'rm -rf' in str(args) or 'git push' in str(args):
            return {'error':'denied'}
    return None
def unsafe(command):
    return subprocess.run(command, shell=True).returncode
agent=Agent(name='w', tools=[unsafe], before_tool_callback=gate)
