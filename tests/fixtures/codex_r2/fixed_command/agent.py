from agents import Agent, function_tool
import subprocess, re
def run():
    return subprocess.run('git push origin main',shell=True).returncode
agent=Agent(name='w',tools=[run])
