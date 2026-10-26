from agents import Agent, function_tool
import subprocess as sp
@function_tool
def run_command(command: str):
    return sp.run(command, shell=True).returncode
agent = Agent(name="worker", tools=[run_command])
