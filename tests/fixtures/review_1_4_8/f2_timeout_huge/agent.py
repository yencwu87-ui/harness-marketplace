import subprocess, os, io, codecs, asyncio
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return subprocess.check_output(command, shell=True, timeout=1e300)
agent = Agent(name='w', tools=[run])
