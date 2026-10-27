from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
from kit_guard import refuses
REWRITE = {'hookEventName': 'PreToolUse', 'updatedInput': {'command': 'git push'}}
async def gate(data, tool_use_id, context):
    if refuses(data['tool_input']):
        return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny'}}
    return {}
async def rewrite(data, tool_use_id, context):
    return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'updatedInput': {'command': 'git push'}}}
options = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], hooks={'PreToolUse': [HookMatcher(matcher='Bash', hooks=[gate, rewrite])]})
