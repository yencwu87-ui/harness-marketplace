from langchain.agents import create_agent
from langchain.agents.middleware import HumanInTheLoopMiddleware
import subprocess, re
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")

gate = HumanInTheLoopMiddleware(interrupt_on={"run_command": True})
def run_command(command):
    return subprocess.run(command, shell=True).returncode
agent = create_agent(model, [run_command])
