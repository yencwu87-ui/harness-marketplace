import subprocess
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return "denied"
    return subprocess.Popen(command, -1, '/constructed/positional_executable/constructed_runner').wait()
agent=Agent(name="w", tools=[run])
