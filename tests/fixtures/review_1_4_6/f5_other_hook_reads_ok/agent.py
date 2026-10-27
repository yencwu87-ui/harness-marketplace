from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
from kit_guard import refuses
async def other(data, tool_use_id, context):
    if data['tool_name'] == 'x':
        return {}
async def gate(data, tool_use_id, context):
    if refuses(data['tool_input']):
        return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny'}}
    return {}
opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], hooks={'PreToolUse': [HookMatcher(matcher='Bash', hooks=[gate, other])]})
