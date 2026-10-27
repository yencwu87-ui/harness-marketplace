import subprocess, re
from pathlib import Path
from agents import Agent
def action():
    return subprocess.run('git push origin main', shell=True).returncode
def run():
    return action()
agent = Agent(name='w', tools=[run])
