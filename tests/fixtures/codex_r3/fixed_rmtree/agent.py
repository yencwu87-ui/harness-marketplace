import subprocess, re
from pathlib import Path
from agents import Agent
import shutil
def run():
    shutil.rmtree('/constructed/work')
    return 'ok'
agent = Agent(name='w', tools=[run])
