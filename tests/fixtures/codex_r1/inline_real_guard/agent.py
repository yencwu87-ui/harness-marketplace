from agents import Agent, function_tool
import subprocess, re
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
@function_tool
def run_shell(command: str) -> str:
    """Execute a shell command."""
    if SECRET.search(command) or any(x in command for x in ("git push", "reset --hard", "rm -rf")):
        return "denied"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
agent = Agent(name="worker", tools=[run_shell])
