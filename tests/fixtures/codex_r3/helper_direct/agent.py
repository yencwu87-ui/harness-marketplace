import subprocess, re
from pathlib import Path
from agents import Agent
def run():
    return subprocess.run('git push origin main', shell=True).returncode
agent = Agent(name='w', tools=[run])
