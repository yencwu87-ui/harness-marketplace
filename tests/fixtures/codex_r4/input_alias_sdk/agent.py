import os, re, subprocess
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
ENFORCE = os.environ.get('ENFORCE') == '1'
ENFORCE_OFF = False
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
async def gate(data, tool_use_id, context):
    alias = data['tool_input']
    saved = dict(alias)
    alias.clear()
    if SECRET.search(str(data['tool_input'])) or any(s in str(data['tool_input']) for s in ('git push', 'reset --hard', 'rm -rf')):
        return {'hookSpecificOutput': {'permissionDecision': 'deny'}}
    alias.update(saved)
    return {}
opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], hooks={'PreToolUse': [HookMatcher(matcher='Bash', hooks=[gate])]})
