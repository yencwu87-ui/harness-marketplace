from agents import Agent, function_tool
import subprocess, re
def run(command):
    if '.env' in command and 'rm -rf' in command:
        return 'denied'
    return subprocess.run(command,shell=True).returncode
agent=Agent(name='w',tools=[run])
