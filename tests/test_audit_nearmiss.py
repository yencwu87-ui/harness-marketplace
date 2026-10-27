"""Generated near-miss tests: for every kind of guard the audit credits, a positive case that earns credit and
generated near-misses of it that must not.

The near-misses are the shapes that fooled earlier versions (Codex rounds 1 and 2): a narrower scope, a different
agent, a different MCP server or tool, a condition or flag in front of the guard, a guard behind a symlink to a file
outside the repo, and a Boolean that reads true but means false. Each is built from the same positive case by one
change, so a pass here means the audit noticed that one change.

Every tool here is an unrestricted shell (`run(command)`), so a guard that loses its credit loses all of G1-G3,
except where a case names the checks it targets.
"""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import GUARD, Repo, audit, guards, points

P = "SECRET.search({x}) or any(s in {x} for s in ('git push', 'reset --hard', 'rm -rf'))"
SECRET = 'SECRET = re.compile(r"(\\.env|\\.pem|\\.key|\\.ssh|\\.aws)")\n'
FLAG = "ENFORCE = os.environ.get('ENFORCE') == '1'\n"

# One change to the refusing condition. {x} is the tool input, {n} the tool-name expression, {p} the positive predicate.
PREDICATE_MISSES = {
    "and instead of or": "SECRET.search({x}) and 'rm -rf' in {x}",
    "inverted (not ...)": "not ({p})",
    "not in": "'.env' not in {x} and 'rm -rf' not in {x}",
    "exact match instead of contains": "{x} == '.env' or {x} == 'rm -rf /'",
    "behind a runtime flag": "ENFORCE and ({p})",
    "behind a False constant": "ENFORCE_OFF and ({p})",
    "reads true, means false (is False)": "({p}) is False",
    "another tool's name": "{n} == 'other_tool' and ({p})",
}
# One change to the structure around the refusing `if`.
STRUCTURE_MISSES = {
    "nested under a runtime flag": "    if ENFORCE:\n{refusal}",
    "nested under another tool's name": "    if {n} == 'other_tool':\n{refusal}",
    "inside try/except": "    try:\n{refusal}    except Exception:\n        pass\n",
    "inside a while loop": "    while ENFORCE:\n{refusal}        break\n",
}


def indent(text, by="    "):
    return "".join((by + line if line.strip() else line) + "\n" for line in text.splitlines())


class RefusalKind:
    """A framework's refusing callable: header, input text, tool name, refusal, wiring into the agent."""

    def __init__(self, name, imports, header, x, n, refuse, tail, wire, unwire, other_agent, early_allow=None):
        self.name, self.imports, self.header, self.x, self.n, self.refuse = name, imports, header, x, n, refuse
        self.tail, self.wire, self.unwire, self.other_agent, self.early_allow = tail, wire, unwire, other_agent, early_allow

    def source(self, cond=None, structure=None, wiring=None, prelude=""):
        p = P.format(x=self.x)
        cond = (cond or "{p}").format(x=self.x, n=self.n, p=p)
        refusal = indent(f"if {cond}:\n{indent(self.refuse)}")             # at the function's body level
        if structure:
            refusal = structure.format(n=self.n, refusal=indent(refusal))
        fn = self.header + prelude + refusal + self.tail
        if self.name.startswith("BeforeToolCallEvent"):                   # Strands: the method lives in the Gate class
            fn = indent(fn) + SHELL_TOOL
        return ("import os, re, subprocess\n" + SECRET + FLAG + "ENFORCE_OFF = False\n" + self.imports + fn +
                (wiring if wiring is not None else self.wire))


SHELL_TOOL = "def run(command):\n    return subprocess.run(command, shell=True).returncode\n"
KINDS = [
    RefusalKind("inline refusal (OpenAI Agents SDK)", "from agents import Agent\n", "def run(command):\n", "command", "'run'",
                "return 'denied'", "    return subprocess.run(command, shell=True).returncode\n",
                "agent = Agent(name='w', tools=[run])\n", None, None),
    RefusalKind("before_tool_callback (Google ADK)", "from google.adk.agents import Agent\n",
                "def gate(tool, args, tool_context):\n", "str(args)", "tool.name", "return {'error': 'denied'}",
                "    return None\n" + SHELL_TOOL,
                "agent = Agent(name='w', tools=[run], before_tool_callback=gate)\n", "agent = Agent(name='w', tools=[run])\n",
                "agent = Agent(name='w', tools=[run])\nother = Agent(name='o', tools=[], before_tool_callback=gate)\n",
                early_allow="    if 'safe' in str(args):\n        return None\n"),
    RefusalKind("before-tool-call hook (CrewAI)", "from crewai import Agent\nfrom crewai.hooks import register_before_tool_call_hook\n",
                "def gate(ctx):\n", "str(ctx.tool_input)", "ctx.tool_name", "return False", "    return None\n" + SHELL_TOOL,
                "register_before_tool_call_hook(gate)\nagent = Agent(role='w', goal='g', backstory='b', tools=[run])\n",
                "agent = Agent(role='w', goal='g', backstory='b', tools=[run])\n", None,
                early_allow="    if 'safe' in str(ctx.tool_input):\n        return None\n"),
    RefusalKind("BeforeToolCallEvent hook (Strands)",
                "from strands import Agent\nfrom strands.hooks import HookProvider, BeforeToolCallEvent\n"
                "class Gate(HookProvider):\n    def register_hooks(self, registry, **kw):\n"
                "        registry.add_callback(BeforeToolCallEvent, self.before)\n",
                "def before(self, event):\n", "str(event.tool_use)", "event.tool_use['name']", "event.cancel_tool = 'denied'",
                "", "agent = Agent(tools=[run], hooks=[Gate()])\n", "agent = Agent(tools=[run])\n",
                "agent = Agent(tools=[run])\nother = Agent(tools=[], hooks=[Gate()])\n"),
    RefusalKind("function middleware (Microsoft Agent Framework)", "from agent_framework import Agent, function_middleware\n",
                "@function_middleware\nasync def gate(context, call_next):\n", "str(context.arguments)", "context.function.name",
                "context.result = 'denied'\nreturn", "    await call_next()\n" + SHELL_TOOL,
                "agent = Agent(client, tools=[run], middleware=[gate])\n", "agent = Agent(client, tools=[run])\n",
                "agent = Agent(client, tools=[run])\nother = Agent(client, tools=[], middleware=[gate])\n"),
    RefusalKind("PreToolUse hook (Claude Agent SDK)", "from claude_agent_sdk import ClaudeAgentOptions, HookMatcher\n",
                "async def gate(data, tool_use_id, context):\n    command = data.get('tool_input', {}).get('command', '')\n",
                "command", "data.get('tool_name')", "return {'hookSpecificOutput': {'permissionDecision': 'deny'}}",
                "    return {}\n",
                "opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], hooks={'PreToolUse': [HookMatcher(matcher='Bash', hooks=[gate])]})\n",
                "opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'])\n",
                "opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], hooks={'PreToolUse': [HookMatcher(matcher='Read', hooks=[gate])]})\n",
                early_allow="    if 'safe' in command:\n        return {}\n"),
]


def score(files):
    with Repo(files) as d:
        rep = audit(d)
        return points(rep), {c: g["status"] for c, g in guards(rep).items()}


class GeneratedNearMisses(unittest.TestCase):
    def build(self, kind, **kw):
        return {"agent.py": kind.source(**kw)}

    def test_every_refusal_kind_positive_earns_full_credit(self):
        for kind in KINDS:
            with self.subTest(kind=kind.name):
                self.assertEqual(score(self.build(kind)), (8, dict.fromkeys(GUARD, "VERIFIED")), self.build(kind)["agent.py"])

    def test_predicate_near_misses_earn_nothing(self):
        for kind in KINDS:
            for miss, cond in PREDICATE_MISSES.items():
                with self.subTest(kind=kind.name, near_miss=miss):
                    files = self.build(kind, cond=cond)
                    pts, st = score(files)
                    self.assertEqual(pts, 0, (st, files["agent.py"]))

    def test_structure_near_misses_earn_nothing(self):
        for kind in KINDS:
            for miss, structure in STRUCTURE_MISSES.items():
                with self.subTest(kind=kind.name, near_miss=miss):
                    files = self.build(kind, structure=structure)
                    pts, st = score(files)
                    self.assertEqual(pts, 0, (st, files["agent.py"]))

    def test_an_earlier_exit_that_lets_calls_through_earns_nothing(self):
        for kind in (k for k in KINDS if k.early_allow):
            with self.subTest(kind=kind.name):
                files = self.build(kind, prelude=kind.early_allow)
                self.assertEqual(score(files)[0], 0, files["agent.py"])

    def test_unattached_or_attached_to_another_agent_earns_nothing(self):
        for kind in KINDS:
            for label, wiring in (("unattached", kind.unwire), ("another agent or matcher", kind.other_agent)):
                if wiring is None:
                    continue
                with self.subTest(kind=kind.name, near_miss=label):
                    files = self.build(kind, wiring=wiring)
                    self.assertEqual(score(files)[0], 0, files["agent.py"])

    def test_a_guard_behind_a_symlink_out_of_the_repo_earns_nothing(self):
        """The guard module (or the settings file) is a link to a file outside the audited tree."""
        outside = Path(tempfile.mkdtemp())
        try:
            (outside / "policy.py").write_text("import re\n" + SECRET + "def gate(tool, args, tool_context):\n"
                                               f"    if {P.format(x='str(args)')}:\n        return {{'error': 'denied'}}\n    return None\n")
            (outside / "settings.json").write_text(json.dumps({"permissions": {"ask": ["Bash(*)", "WebFetch", "Write", "Edit"]}}))
            src = ("import subprocess\nfrom google.adk.agents import Agent\nfrom policy import gate\n" + SHELL_TOOL +
                   "agent = Agent(name='w', tools=[run], before_tool_callback=gate)\n")
            with Repo({"agent.py": src}) as d:
                (d / "policy.py").write_text((outside / "policy.py").read_text())
                self.assertEqual(points(audit(d)), 8)                   # the same guard, inside the repo
                (d / "policy.py").unlink()
                (d / "policy.py").symlink_to(outside / "policy.py")
                self.assertEqual(points(audit(d)), 0)
            with Repo({}) as d:
                (d / ".claude").mkdir()
                (d / ".claude" / "settings.json").symlink_to(outside / "settings.json")
                self.assertEqual(points(audit(d)), 0)
        finally:
            shutil.rmtree(outside)


def claude(perms, sandbox=False):
    data = {"permissions": perms}
    if sandbox:
        data["sandbox"] = {"enabled": True, "autoAllowBashIfSandboxed": True}
    return {".claude/settings.json": json.dumps(data)}


ONLY_BASH = ["Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "Read", "Grep", "Glob"]


class ApprovalNearMisses(unittest.TestCase):
    """Approvals and permission rules: the positive, then each one-change near-miss."""

    def cases(self):
        oai = "import subprocess\nfrom agents import Agent, function_tool\n@function_tool(needs_approval={v})\n" + SHELL_TOOL + \
              "@function_tool\ndef other_tool(command):\n    return 'ok'\nagent = Agent(name='w', tools=[run, other_tool])\n"
        oai_other = "import subprocess\nfrom agents import Agent, function_tool\n@function_tool\n" + SHELL_TOOL + \
                    "@function_tool(needs_approval=True)\ndef other_tool(command):\n    return 'ok'\nagent = Agent(name='w', tools=[run, other_tool])\n"
        maf = "import subprocess\nfrom agent_framework import Agent, tool\n@tool(approval_mode={v})\n" + SHELL_TOOL + \
              "agent = Agent(client, tools=[run])\n"
        lg = ("import subprocess\nfrom langchain.agents import create_agent\nfrom langchain.agents.middleware import HumanInTheLoopMiddleware\n"
              "gate = HumanInTheLoopMiddleware(interrupt_on={v})\n" + SHELL_TOOL + "agent = create_agent(model, [run], middleware=[gate])\n")
        sdk = "from claude_agent_sdk import ClaudeAgentOptions\nopts = ClaudeAgentOptions(tools=['Bash'], allowed_tools={v})\n"
        mcp = ("from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, tool\nimport subprocess\n"
               "@tool('execute', 'run', {{'command': str}})\ndef unsafe(args):\n    return subprocess.run(args['command'], shell=True).returncode\n"
               "@tool('execute', 'fixed', {{}})\ndef narrow(args):\n    return 'fixed'\n"
               "prod = create_sdk_mcp_server(name='prod', tools=[{attached}])\n"
               "opts = ClaudeAgentOptions(tools=[], allowed_tools=['mcp__prod__execute'], mcp_servers={{'prod': prod}})\n")
        return {
            "needs_approval": ({"agent.py": oai.format(v="True")}, {
                "needs_approval=False": {"agent.py": oai.format(v="False")},
                "needs_approval='False' (a string)": {"agent.py": oai.format(v="'False'")},
                "needs_approval=<a function>": {"agent.py": oai.format(v="lambda ctx, args, call_id: False")},
                "on another tool": {"agent.py": oai_other}}),
            "approval_mode": ({"agent.py": maf.format(v="'always_require'")}, {
                "never_require": {"agent.py": maf.format(v="'never_require'")}}),
            "HumanInTheLoopMiddleware": ({"agent.py": lg.format(v="{'run': True}")}, {
                "interrupt_on run False": {"agent.py": lg.format(v="{'run': False}")},
                "interrupt_on another tool": {"agent.py": lg.format(v="{'other_tool': True}")},
                "not passed to the agent": {"agent.py": lg.format(v="{'run': True}").replace(", middleware=[gate]", "")}}),
            "SDK tool needs approval": ({"agent.py": sdk.format(v="[]")}, {
                "auto-allowed": {"agent.py": sdk.format(v="['Bash']")},
                "auto-allowed by a pattern": {"agent.py": sdk.format(v="['Bash(*)']")}}),
            "SDK MCP tool": ({"agent.py": mcp.format(attached="narrow")}, {
                "the same name, the other implementation attached": {"agent.py": mcp.format(attached="unsafe")},
                "attached to a server the options do not use": {"agent.py": mcp.format(attached="narrow").replace(
                    "opts = ", "other = create_sdk_mcp_server(name='x', tools=[unsafe])\nopts = ").replace("{'prod': prod}", "{'prod': other}")}}),
            "Claude Code ask": (claude({"allow": ["Bash(*)"], "ask": ["Bash(*)"], "deny": ONLY_BASH}), {
                "scoped ask": claude({"allow": ["Bash(*)"], "ask": ["Bash(git status *)"], "deny": ONLY_BASH}),
                "ask on another tool": claude({"allow": ["Bash(*)"], "ask": ["Write"], "deny": [t for t in ONLY_BASH if t != "Write"]}),
                "ask with a narrower prefix": claude({"allow": ["Bash(*)"], "ask": ["Bash(git *)"], "deny": ONLY_BASH})}),
        }

    def test_positives_earn_full_credit_and_near_misses_earn_nothing(self):
        for kind, (positive, misses) in self.cases().items():
            with self.subTest(kind=kind, case="positive"):
                self.assertEqual(score(positive)[0], 8, (score(positive), positive))
            for miss, files in misses.items():
                with self.subTest(kind=kind, near_miss=miss):
                    self.assertEqual(score(files)[0], 0, (score(files), files))

    def test_claude_rule_scope_near_misses(self):
        """Deny rules: the kit template's patterns earn credit; a narrower copy of each earns nothing for its check."""
        base = {"deny": ["Read(./**/.env)", "Read(./**/.env.*)", "Read(./**/*.key)", "Read(./**/*.pem)", "Read(~/.ssh/**)",
                         "Read(~/.aws/**)", "Bash(git push *)", "Bash(git reset --hard *)", "Bash(rm -rf *)"]}
        self.assertEqual(score(claude(base, sandbox=True))[1], dict.fromkeys(GUARD, "VERIFIED"))
        narrow_secret = {"deny": ["Read(./docs/.env.example)", "Read(./config/.env)", "Bash(git push *)", "Bash(rm -rf *)"]}
        st = score(claude(narrow_secret, sandbox=True))[1]
        self.assertNotEqual(st["G2"], "VERIFIED", st)
        narrow_destructive = {"deny": base["deny"][:6] + ["Bash(git push origin main)", "Bash(rm -rf /tmp/x)"]}
        st = score(claude(narrow_destructive, sandbox=True))[1]
        self.assertNotEqual(st["G3"], "VERIFIED", st)
        cat_only = {"deny": ["Bash(cat *.env*)", "Bash(git push *)"]}       # secrets refused only for `cat`, no Read rules
        st = score(claude(cat_only | {"allow": ["Read"]}, sandbox=True))[1]
        self.assertNotEqual(st["G2"], "VERIFIED", st)

    def test_crewai_task_human_input_is_never_a_per_call_approval(self):
        src = ("import subprocess\nfrom crewai import Agent, Task\n" + SHELL_TOOL +
               "worker = Agent(role='w', goal='g', backstory='b', tools=[run])\n"
               "task = Task(description='d', expected_output='o', agent=worker, human_input=True)\n")
        self.assertEqual(score({"agent.py": src})[0], 0)


if __name__ == "__main__":
    unittest.main()
