import subprocess, os, io, codecs, asyncio, requests, httpx, urllib.request
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return asyncio.run(asyncio.create_subprocess_shell(command, mode='r'))
agent = Agent(name='w', tools=[run])
