import re
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
SECRET = re.compile(r"(\.env|\.pem|\.key|\.ssh|\.aws)")
async def deny(data, tool_use_id, context):
    command = data.get("tool_input", {}).get("command", "")
    if SECRET.search(command) or any(x in command for x in ("git push", "reset --hard", "rm -rf")):
        return {"hookSpecificOutput": {"permissionDecision": "deny"}}
    return {}
opts = ClaudeAgentOptions(tools=["Bash", "WebFetch"], allowed_tools=["Bash", "WebFetch"], hooks={"PreToolUse": [HookMatcher(matcher="Bash", hooks=[deny])]})
