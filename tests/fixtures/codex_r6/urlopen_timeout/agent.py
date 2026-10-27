from agents import Agent
import urllib.request
from kit_guard import refuses
def fetch(url):
    if refuses(url):
        return 'denied'
    return urllib.request.urlopen(url, timeout=5)
agent=Agent(name='w', tools=[fetch])
