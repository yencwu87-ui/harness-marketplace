from agents import Agent
import urllib.request
from kit_guard import refuses
def fetch(url):
    if refuses(url):
        return 'denied'
    return urllib.request.urlopen(url, follow_redirects=True)
agent=Agent(name='w', tools=[fetch])
