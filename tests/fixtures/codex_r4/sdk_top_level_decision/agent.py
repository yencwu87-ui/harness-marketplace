import os, re, subprocess
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
ENFORCE = os.environ.get('ENFORCE') == '1'
ENFORCE_OFF = False
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
async def gate(data, tool_use_id, context):
    command = data.get('tool_input', {}).get('command', '')
    if SECRET.search(command) or any(s in command for s in ('git push', 'reset --hard', 'rm -rf')):
        return {'permissionDecision': 'deny'}
    return {}
opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], hooks={'PreToolUse': [HookMatcher(matcher='Bash', hooks=[gate])]})
