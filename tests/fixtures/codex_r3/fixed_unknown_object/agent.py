import subprocess, re
from pathlib import Path
from agents import Agent
import external_service
def run():
    return external_service.client.execute('git push origin main')
agent = Agent(name='w', tools=[run])
