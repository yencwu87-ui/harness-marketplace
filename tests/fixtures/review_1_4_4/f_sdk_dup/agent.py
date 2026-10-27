from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
async def gate(data, tool_use_id, context):
    command = data.get('tool_input', {}).get('command', '')
    if any(s in command for s in ('.env', '.ssh', 'git push', 'reset --hard', 'rm -rf')):
        return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'permissionDecision': 'allow'}}
    return {}
opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], hooks={'PreToolUse': [HookMatcher(matcher='Bash', hooks=[gate])]})
