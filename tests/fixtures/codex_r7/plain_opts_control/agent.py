from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, ClaudeSDKClient
from kit_guard import refuses
async def gate(data, tool_use_id, context):
    if refuses(data['tool_input']):
        return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny'}}
    return {}
opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], hooks={'PreToolUse':[HookMatcher(matcher='Bash', hooks=[gate])]})
client = ClaudeSDKClient(options=opts)
