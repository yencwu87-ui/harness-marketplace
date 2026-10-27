import subprocess, re
from pathlib import Path
from agents import Agent
def run(command):
    if re.match(r'\.env|rm -rf|git push', command):
        return 'denied'
    return subprocess.run(command, shell=True).returncode
agent = Agent(name='w', tools=[run])
