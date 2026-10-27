from agents import Agent, function_tool
import subprocess, re
def run(command):
    runner = subprocess
    return runner.run(command,shell=True).returncode
agent=Agent(name='w',tools=[run])
