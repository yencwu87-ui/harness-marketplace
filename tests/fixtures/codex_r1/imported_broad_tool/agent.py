from agents import Agent
from tool_impl import run_command
agent = Agent(name="worker", tools=[run_command])
