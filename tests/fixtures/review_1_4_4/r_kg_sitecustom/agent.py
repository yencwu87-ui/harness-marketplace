import subprocess, kit_guard, other
from agents import Agent
def run(command):
    if kit_guard.refuses(command):
        return 'denied'
    return subprocess.run(command, shell=True).returncode
agent = Agent(name='w', tools=[run])
