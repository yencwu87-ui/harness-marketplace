import subprocess, re
from pathlib import Path
from agents import Agent
def run():
    return Path('.env').read_text()
agent = Agent(name='w', tools=[run])
