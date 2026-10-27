from agents import Agent, function_tool
import subprocess, re
from pathlib import Path
def read(path):
    with Path(path).open() as f:
        return f.read()
agent=Agent(name='w',tools=[read])
