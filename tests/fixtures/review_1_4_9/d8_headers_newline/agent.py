import subprocess, requests
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return requests.get(command, headers={'a': 'b\nX: y'}).text
agent=Agent(name='w', tools=[run])
