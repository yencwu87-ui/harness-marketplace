from claude_agent_sdk import ClaudeAgentOptions
opts=ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], disallowed_tools=['Bash(cat *.env*)','Bash(git push origin main)'])
