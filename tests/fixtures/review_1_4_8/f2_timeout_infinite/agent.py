import subprocess, os, io, codecs, asyncio
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return subprocess.run(command, shell=True, capture_output=True, timeout=1e400)
agent = Agent(name='w', tools=[run])
