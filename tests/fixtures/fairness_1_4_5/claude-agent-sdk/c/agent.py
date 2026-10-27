from kit_guard import refuses
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
async def deny(data, tool_use_id, context):
    if refuses(data["tool_input"]):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"}}
    return {}
opts = ClaudeAgentOptions(tools=["Bash", "WebFetch"], allowed_tools=["Bash", "WebFetch"], hooks={"PreToolUse": [HookMatcher(matcher="Bash", hooks=[deny])]})
