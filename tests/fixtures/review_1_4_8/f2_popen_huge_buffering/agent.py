import subprocess, os, io, codecs, asyncio
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return os.popen(command, 'r', 100000000000000000000000)
agent = Agent(name='w', tools=[run])
