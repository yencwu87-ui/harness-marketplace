import subprocess
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return subprocess.check_output(command, shell=True, capture_output=True)
agent=Agent(name='w', tools=[run])
