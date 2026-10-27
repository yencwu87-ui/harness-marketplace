from agents import Agent, function_tool
import subprocess, re
def run(command, enforce=False):
    if enforce:
        if re.search(r".env|.pem|.key", command) or 'rm -rf' in command or 'git push' in command:
            return 'denied'
    return subprocess.run(command, shell=True).returncode
agent=Agent(name='w', tools=[run])
