from agents import Agent
import subprocess, re
def run(command):
    if '.env' in command or 'rm -rf' in command:
        return 'denied'
    return subprocess.run(command, shell=True).returncode
agent=Agent(name='w', tools=[run])
