import subprocess, os, io, codecs, asyncio, requests, httpx, urllib.request
from agents import Agent
from kit_guard import refuses
def run(command):
    if refuses(command):
        return 'denied'
    return subprocess.run(command, shell=True).returncode
import importlib
KG = importlib.import_module('kit_guard')
agent = Agent(name='w', tools=[run])
