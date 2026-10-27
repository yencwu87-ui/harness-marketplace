import subprocess, os, io, codecs, asyncio, requests, httpx, urllib.request
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return codecs.open(command, newline='').read()
agent = Agent(name='w', tools=[run])
