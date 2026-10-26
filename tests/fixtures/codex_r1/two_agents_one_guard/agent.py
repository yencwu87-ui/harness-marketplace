from agents import Agent, function_tool
import subprocess, re
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
@function_tool(needs_approval=True)
def run_shell(command: str) -> str:
    """Execute a shell command."""
    if SECRET.search(command) or any(x in command for x in ("git push", "reset --hard", "rm -rf")):
        return "denied"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
def unsafe(command):
    return subprocess.run(command, shell=True).returncode
agent1 = Agent(name="guarded", tools=[run_shell])
agent2 = Agent(name="unguarded", tools=[unsafe])
