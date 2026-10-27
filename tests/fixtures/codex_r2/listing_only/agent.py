from agents import Agent
import os
def listing(path):
    return os.listdir(path)
agent=Agent(name='w',tools=[listing])
