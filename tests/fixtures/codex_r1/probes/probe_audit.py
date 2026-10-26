import importlib.util, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORK = ROOT / 'work'
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod
audit = load(WORK / 'plugins/harness-audit/skills/audit/scripts/audit.py', 'candidate_audit')
base = load(ROOT / 'base_audit.py', 'base_audit')

FRAMEWORKS = {
 'langgraph': ('from langchain.agents import create_agent\nfrom langchain_core.tools import tool\n', '@tool', 'agent = create_agent(model, TOOLS{extra})'),
 'openai-agents-sdk': ('from agents import Agent, function_tool\n', '@function_tool', 'agent = Agent(name="worker", tools=TOOLS{extra})'),
 'crewai': ('from crewai import Agent\nfrom crewai.tools import tool\n', '@tool("{name}")', 'agent = Agent(role="worker", goal="work", backstory="worker", tools=TOOLS{extra})'),
 'strands-agents': ('from strands import Agent, tool\n', '@tool', 'agent = Agent(tools=TOOLS{extra})'),
 'google-adk': ('from google.adk.agents import Agent\n', '', 'agent = Agent(name="worker", tools=TOOLS{extra})'),
 'microsoft-agent-framework': ('from agent_framework import Agent, tool\n', '@tool', 'agent = Agent(client, tools=TOOLS{extra})'),
}
SECRET = 'SECRET = re.compile(r"(\\.env|\\.pem|\\.key|\\.ssh|\\.aws)")\n'
SHELL = 'def run_shell(command: str) -> str:\n    """Execute a shell command."""\n{guard}    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout\n'
FETCH = 'def fetch(url: str) -> str:\n    """Fetch a URL."""\n    return urllib.request.urlopen(url).read().decode()\n'
GUARD = '    if SECRET.search(command) or any(x in command for x in ("git push", "reset --hard", "rm -rf")):\n        return "denied"\n'

def write(path, fw, variant):
    path.mkdir(parents=True, exist_ok=True)
    if fw == 'claude-code':
        (path/'.claude').mkdir(exist_ok=True)
        deny = [] if variant == 'b' else ['Read(**/.env*)', 'Read(**/*.pem)', 'Read(**/*.key)', 'Read(**/.ssh/**)', 'Read(**/.aws/**)', 'Bash(git push *)', 'Bash(git reset --hard *)', 'Bash(rm -rf *)']
        if variant == 'a': deny += ['Bash(*)', 'Write(*)', 'Edit(*)', 'WebFetch', 'WebSearch']
        # c guards shell/secret file reads; WebFetch is still broad and ungated.
        (path/'.claude/settings.json').write_text(json.dumps({'permissions': {'deny': deny, 'allow': ['Bash(*)','WebFetch'] if variant != 'a' else [], 'ask': ['Bash(*)'] if variant == 'c' else []}}))
        return
    if fw == 'claude-agent-sdk':
        src = 'import re\nfrom claude_agent_sdk import ClaudeAgentOptions, HookMatcher\n'
        if variant == 'a':
            src += 'opts = ClaudeAgentOptions(tools=[], allowed_tools=[])\n'
        elif variant == 'b':
            src += 'opts = ClaudeAgentOptions(tools=["Bash", "WebFetch"], allowed_tools=["Bash", "WebFetch"])\n'
        else:
            src += SECRET + 'async def deny(data, tool_use_id, context):\n    command = data.get("tool_input", {}).get("command", "")\n    if SECRET.search(command) or any(x in command for x in ("git push", "reset --hard", "rm -rf")):\n        return {"hookSpecificOutput": {"permissionDecision": "deny"}}\n    return {}\nopts = ClaudeAgentOptions(tools=["Bash", "WebFetch"], allowed_tools=["Bash", "WebFetch"], hooks={"PreToolUse": [HookMatcher(matcher="Bash", hooks=[deny])]})\n'
        (path/'agent.py').write_text(src)
        return
    imports, deco, build = FRAMEWORKS[fw]
    src = 'import re, subprocess, urllib.request\n' + imports
    extra = ''
    if variant == 'a':
        src += deco.format(name='next_item') + '\ndef next_item() -> str:\n    """Return a fixed work item."""\n    return "F-001"\nTOOLS = [next_item]\n'
    else:
        if variant == 'c': src += SECRET
        shell_deco = deco.format(name='run_shell')
        if variant == 'c':
            if fw == 'openai-agents-sdk': shell_deco = '@function_tool(needs_approval=True)'
            elif fw == 'microsoft-agent-framework': shell_deco = '@tool(approval_mode="always_require")'
            elif fw == 'langgraph':
                src += 'from langchain.agents.middleware import HumanInTheLoopMiddleware\ngate = HumanInTheLoopMiddleware(interrupt_on={"run_shell": True})\n'
                extra = ', middleware=[gate]'
            elif fw == 'crewai':
                src += 'from crewai.hooks import register_before_tool_call_hook\ndef gate(ctx):\n    if ctx.tool_name == "run_shell" and (SECRET.search(str(ctx.tool_input)) or "rm -rf" in str(ctx.tool_input)):\n        return False\n    return None\nregister_before_tool_call_hook(gate)\n'
            elif fw == 'google-adk':
                src += 'def gate(tool, args, tool_context):\n    if tool.name == "run_shell" and (SECRET.search(str(args)) or "rm -rf" in str(args)):\n        return {"error": "denied"}\n    return None\n'
                extra = ', before_tool_callback=gate'
            elif fw == 'strands-agents':
                src += 'from strands.hooks import HookProvider, BeforeToolCallEvent\nclass Gate(HookProvider):\n    def register_hooks(self, registry, **kwargs):\n        registry.add_callback(BeforeToolCallEvent, self.before)\n    def before(self, event):\n        if event.tool_use["name"] == "run_shell" and (SECRET.search(str(event.tool_use)) or "rm -rf" in str(event.tool_use)):\n            event.cancel_tool = "denied"\n'
                extra = ', hooks=[Gate()]'
        src += shell_deco + '\n' + SHELL.format(guard=GUARD if variant == 'c' else '')
        src += deco.format(name='fetch') + '\n' + FETCH
        src += 'TOOLS = [run_shell, fetch]\n'
    src += build.format(extra=extra) + '\n'
    (path/'agent.py').write_text(src)

def summarize(rep):
    guards = [c for c in rep.checks if c['id'] in ('G1','G2','G3')]
    return {'total_score': rep.score, 'guard_points': sum(c['weight'] * {'VERIFIED':1,'DECLARED':.5}.get(c['status'],0) for c in guards), 'guards': guards}

results = {'matrix': {}, 'extra': {}, 'claude_base_compare': {}}
for fw in ['claude-code', 'claude-agent-sdk', *FRAMEWORKS]:
    results['matrix'][fw] = {}
    for v in 'abc':
        p = ROOT/'fixtures'/fw/v
        write(p, fw, v)
        results['matrix'][fw][v] = summarize(audit.audit(p))
        if fw == 'claude-code':
            results['claude_base_compare'][v] = {'candidate': summarize(audit.audit(p)), 'base': summarize(base.audit(p))}

extras = {
 'imported_broad_tool': {'agent.py': 'from agents import Agent\nfrom tool_impl import run_command\nagent = Agent(name="worker", tools=[run_command])\n', 'tool_impl.py': 'import subprocess\ndef run_command(command):\n    return subprocess.run(command, shell=True).returncode\n'},
 'aliased_subprocess': {'agent.py': 'from agents import Agent, function_tool\nimport subprocess as sp\n@function_tool\ndef run_command(command: str):\n    return sp.run(command, shell=True).returncode\nagent = Agent(name="worker", tools=[run_command])\n'},
 'unattached_guard': {'agent.py': 'from langchain.agents import create_agent\nfrom langchain.agents.middleware import HumanInTheLoopMiddleware\nimport subprocess, re\n'+SECRET+'\ngate = HumanInTheLoopMiddleware(interrupt_on={"run_command": True})\ndef run_command(command):\n    return subprocess.run(command, shell=True).returncode\nagent = create_agent(model, [run_command])\n'},
 'inline_real_guard': {'agent.py': 'from agents import Agent, function_tool\nimport subprocess, re\n'+SECRET+'@function_tool\n'+SHELL.format(guard=GUARD)+'agent = Agent(name="worker", tools=[run_shell])\n'},
 'two_agents_one_guard': {'agent.py': 'from agents import Agent, function_tool\nimport subprocess, re\n'+SECRET+'@function_tool(needs_approval=True)\n'+SHELL.format(guard=GUARD)+'def unsafe(command):\n    return subprocess.run(command, shell=True).returncode\nagent1 = Agent(name="guarded", tools=[run_shell])\nagent2 = Agent(name="unguarded", tools=[unsafe])\n'},
}
for name, files in extras.items():
    p = ROOT/'fixtures'/name; p.mkdir(parents=True, exist_ok=True)
    for f,t in files.items(): (p/f).write_text(t)
    results['extra'][name] = summarize(audit.audit(p))
for fw, sig in audit.TRACK_SIGNATURES.items():
    if sig['support'] != 'assess-only': continue
    p = ROOT/'fixtures'/'assess'/fw; p.mkdir(parents=True, exist_ok=True)
    pattern, needle = next((f,s) for f,s in sig['detect'] if f in ('requirements*.txt','package.json'))
    (p/('requirements.txt' if pattern == 'requirements*.txt' else 'package.json')).write_text(needle+'==1.0.0' if pattern == 'requirements*.txt' else json.dumps({'dependencies': {needle.strip('"'): '1.0.0'}}))
    (p/'docs').mkdir(exist_ok=True)
    (p/'docs/IMPACT.md').write_text('## Tools\n- next_item only\n## Secrets\n- no file access\n## Destructive actions\n- none\n')
    results['extra']['assess_'+fw] = summarize(audit.audit(p))
p = ROOT/'fixtures'/'mixed'; write(p, 'claude-code','a'); write(p,'openai-agents-sdk','b')
results['extra']['mixed_derived_wins'] = summarize(audit.audit(p))
p = ROOT/'fixtures'/'full_plus_declared'; write(p,'langgraph','b')
(p/'requirements.txt').write_text('pydantic-ai==1.0.0\n')
(p/'docs').mkdir(exist_ok=True)
(p/'docs/IMPACT.md').write_text('## Tools\n- safe\n## Secrets\n- safe\n## Destructive actions\n- safe\n')
results['extra']['full_plus_declared'] = summarize(audit.audit(p))
(ROOT/'audit_probe_results.json').write_text(json.dumps(results,indent=2)+'\n')
for fw,row in results['matrix'].items(): print(fw, [(v,s['guard_points'],s['total_score']) for v,s in row.items()])
for name,r in results['extra'].items(): print(name, r['guard_points'], [(c['id'],c['status']) for c in r['guards']])
