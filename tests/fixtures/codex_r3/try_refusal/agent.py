import subprocess, re
from pathlib import Path
from agents import Agent
def run(command):
    try:
        if '.env' in command or 'rm -rf' in command or 'git push' in command:
            return 'denied'
    except Exception:
        return 'denied'
    return subprocess.run(command, shell=True).returncode
agent = Agent(name='w', tools=[run])
