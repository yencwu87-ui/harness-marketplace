import subprocess, os, io, codecs, asyncio
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return open(command, encoding='hex')
agent = Agent(name='w', tools=[run])
