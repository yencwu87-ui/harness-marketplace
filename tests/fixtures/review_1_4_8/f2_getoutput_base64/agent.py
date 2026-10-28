import subprocess, os, io, codecs, asyncio
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return subprocess.getoutput(command, encoding='base64')
agent = Agent(name='w', tools=[run])
