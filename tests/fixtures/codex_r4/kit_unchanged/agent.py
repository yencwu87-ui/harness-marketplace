from agents import Agent
import subprocess, re
import kit_guard
def run(command):
    if kit_guard.refuses(command):
        return 'denied'
    return subprocess.run(command, shell=True).returncode
agent=Agent(name='w', tools=[run])
