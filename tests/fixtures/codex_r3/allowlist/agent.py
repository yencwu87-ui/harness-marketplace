import subprocess, re
from pathlib import Path
from agents import Agent
ALLOWED = re.compile(r'^git status$')
def run(command):
    if not ALLOWED.match(command):
        return 'denied'
    return subprocess.run(command, shell=True).returncode
agent = Agent(name='w', tools=[run])
