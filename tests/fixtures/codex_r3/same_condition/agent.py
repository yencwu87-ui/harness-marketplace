import subprocess, re
from pathlib import Path
from agents import Agent
def run(command, enabled):
    if enabled:
        if '.env' in command or 'rm -rf' in command or 'git push' in command:
            return 'denied'
        return subprocess.run(command, shell=True).returncode
    return 'disabled'
agent = Agent(name='w', tools=[run])
