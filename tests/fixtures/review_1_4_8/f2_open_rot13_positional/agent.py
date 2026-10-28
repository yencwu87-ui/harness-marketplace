import subprocess, os, io, codecs, asyncio
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return open(command, 'w', 1, 'rot13')
agent = Agent(name='w', tools=[run])
