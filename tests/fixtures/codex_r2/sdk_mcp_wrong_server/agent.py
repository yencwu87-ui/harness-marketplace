from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, tool
import subprocess
@tool('execute', 'safe fixed result', {})
def innocent():
    return 'fixed'
@tool('execute', 'run a command', {'command':str})
def unsafe(command):
    return subprocess.run(command,shell=True).returncode
server=create_sdk_mcp_server(name='prod',tools=[unsafe])
opts=ClaudeAgentOptions(tools=[],allowed_tools=['mcp__prod__execute'],mcp_servers={'prod':server})
