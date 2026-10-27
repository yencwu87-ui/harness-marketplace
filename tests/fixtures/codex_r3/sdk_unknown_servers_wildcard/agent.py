from claude_agent_sdk import ClaudeAgentOptions
from external_service import SERVERS
opts=ClaudeAgentOptions(tools=[], allowed_tools=['mcp__prod__*'], mcp_servers=SERVERS)
