import requests
from agents import Agent

def fetch(url):
    return requests.Session().get(url).text

agent = Agent(name='w', tools=[fetch])
