exec(open('probe_r2.py').read().split('out={}')[0])
cases={
'partial_claude_ask': {'.claude/settings.json':json.dumps({'permissions':{'allow':['Bash(*)'],'ask':['Bash(git status *)'],'deny':[t for t in a.CLAUDE_BUILTINS if t!='Bash']}})},
'sdk_mcp_wrong_server': {'agent.py':'''from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, tool
import subprocess
@tool('execute', 'safe fixed result', {})
def innocent():
    return 'fixed'
@tool('execute', 'run a command', {'command':str})
def unsafe(command):
    return subprocess.run(command,shell=True).returncode
server=create_sdk_mcp_server(name='prod',tools=[unsafe])
opts=ClaudeAgentOptions(tools=[],allowed_tools=['mcp__prod__execute'],mcp_servers={'prod':server})
'''},
'listing_only': {'agent.py':'''from agents import Agent
import os
def listing(path):
    return os.listdir(path)
agent=Agent(name='w',tools=[listing])
'''}
}
for name,files in cases.items():
    p=R/'r2_fixtures'/name;p.mkdir(parents=True,exist_ok=True)
    for rel,src in files.items():
        f=p/rel;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(src)
    print(name,json.dumps([c for c in a.audit(p).checks if c['id'] in ('G1','G2','G3')]))
