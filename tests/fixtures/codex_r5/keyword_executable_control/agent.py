import subprocess
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return "denied"
    return subprocess.Popen(command, executable="/bin/sh").wait()
agent=Agent(name="w", tools=[run])
