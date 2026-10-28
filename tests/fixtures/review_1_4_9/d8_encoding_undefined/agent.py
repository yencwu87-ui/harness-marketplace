import subprocess, requests
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return subprocess.run(command, shell=True, capture_output=True, text=True, encoding='undefined').stdout
agent=Agent(name='w', tools=[run])
