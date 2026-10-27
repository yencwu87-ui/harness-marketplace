from agents import Agent
import urllib.request
from kit_guard import refuses
def fetch(url):
    if refuses(url):
        return 'denied'
    return urllib.request.urlopen(url, headers={'X':'a'})
agent=Agent(name='w', tools=[fetch])
