from crewai import Agent, Task
import subprocess
def run(command):
    return subprocess.run(command,shell=True).returncode
safe=Agent(role='safe', goal='g', backstory='b', tools=[])
unsafe=Agent(role='unsafe', goal='g', backstory='b', tools=[run])
task=Task(description='review safe work', expected_output='report', agent=safe, human_input=True)
