import subprocess, re
from pathlib import Path
from agents import Agent
def run(command, label=''):
    if '.env' in label or 'rm -rf' in label or 'git push' in label:
        return 'denied'
    return subprocess.run(command, shell=True).returncode
agent = Agent(name='w', tools=[run])
