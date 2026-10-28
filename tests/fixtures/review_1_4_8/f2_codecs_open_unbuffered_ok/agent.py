import subprocess, os, io, codecs, asyncio
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return codecs.open(command, 'r', 'utf-8', 'strict', 0)
agent = Agent(name='w', tools=[run])
