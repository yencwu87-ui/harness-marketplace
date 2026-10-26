import re
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
opts = ClaudeAgentOptions(tools=["Bash", "WebFetch"], allowed_tools=["Bash", "WebFetch"])
