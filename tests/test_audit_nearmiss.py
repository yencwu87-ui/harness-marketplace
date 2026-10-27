"""Generated near-miss tests: for every kind of guard the audit credits, a positive case that earns credit and
generated near-misses of it that must not.

The near-misses are the shapes that fooled earlier versions (Codex rounds 1 to 3): a narrower scope, a different
agent, a different MCP server or tool, a condition or flag in front of the guard, a guard behind a symlink to a file
outside the repo, and a Boolean that reads true but means false. Round 3 (1.4.4) adds: `for` versus `while`, a
loop-local exit versus a function-level refusal, the right versus the wrong input field or parameter, rebinding after
capturing an input, readable helpers that always (or never) refuse, anchored versus unanchored regexes, reach through
zero-input helpers, wildcard approval with an MCP map the audit cannot read, and directory versus file symlinks.
Each is built from the same positive case by one change, so a pass here means the audit noticed that one change.
From 1.4.4 the positives are written in the canonical guard forms (`audit.py --canonical-forms`).

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
    "and hidden inside any(...)": "any(SECRET.search(c) and 'rm -rf' in c for c in [{x}])",
    "all(...) instead of any(...)": "all(s in {x} for s in ('.env', 'git push', 'reset --hard', 'rm -rf'))",
    "any(...) filtered to some inputs": "any(SECRET.search(c) or 'rm -rf' in c for c in [{x}] if c.startswith('cat'))",
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

    def source(self, cond=None, structure=None, wiring=None, prelude="", module="", refuse=None, x=None, header=None,
               tail=None):
        x = x or self.x
        p = P.format(x=x)
        cond = (cond or "{p}").format(x=x, n=self.n, p=p)
        refusal = indent(f"if {cond}:\n{indent(refuse or self.refuse)}")   # at the function's body level
        if structure:
            refusal = structure.format(n=self.n, refusal=indent(refusal))
        fn = (header or self.header) + prelude + refusal + (self.tail if tail is None else tail)
        if self.name.startswith("BeforeToolCallEvent"):                   # Strands: the method lives in the Gate class
            fn = indent(fn) + SHELL_TOOL
        return ("import os, re, subprocess\n" + SECRET + FLAG + "ENFORCE_OFF = False\n" + module + self.imports + fn +
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
        data["sandbox"] = {"enabled": True, "autoAllowBashIfSandboxed": True, "allowUnsandboxedCommands": False}
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



# ------------------------------------------------------------------ 1.4.4: Codex round-3 families
# Per kind: a value that is not the tool's input (wrong parameter or field), and a change to the input before the test.
WRONG_VALUE = {
    "inline refusal (OpenAI Agents SDK)": dict(x="label", header="def run(command, label=''):\n"),
    "before_tool_callback (Google ADK)": dict(x="str(tool_context)"),
    "before-tool-call hook (CrewAI)": dict(x="str(ctx)"),
    "BeforeToolCallEvent hook (Strands)": dict(x="str(event.selected_tool)"),
    "function middleware (Microsoft Agent Framework)": dict(x="str(context.function)"),
    "PreToolUse hook (Claude Agent SDK)": dict(x="description", header="async def gate(data, tool_use_id, context):\n"
                                               "    description = data.get('tool_input', {}).get('description', '')\n"),
}
REBIND = {
    "inline refusal (OpenAI Agents SDK)": dict(prelude="    original = command\n    command = ''\n",
                                               tail="    return subprocess.run(original, shell=True).returncode\n"),
    "before_tool_callback (Google ADK)": dict(prelude="    args.clear()\n"),
    "before-tool-call hook (CrewAI)": dict(prelude="    ctx.tool_input = {}\n"),
    "BeforeToolCallEvent hook (Strands)": dict(prelude="    event.tool_use = {}\n"),
    "function middleware (Microsoft Agent Framework)": dict(prelude="    context.arguments = {}\n"),
    "PreToolUse hook (Claude Agent SDK)": dict(prelude="    command = ''\n"),
}
LOOP_MISSES = {
    "inside a for loop over a literal": "    for _ in [1]:\n{refusal}",
    "inside an empty for loop": "    for _ in []:\n{refusal}",
    "inside a for loop over range(1)": "    for _ in range(1):\n{refusal}",
    "inside while True ... break": "    while True:\n{refusal}        break\n",
    "inside a with block": "    with open(os.devnull):\n{refusal}",
}
LOOP_LOCAL_EXITS = {"continue": "continue", "break": "break"}
HELPERS = {          # a readable helper decides; none of these is a canonical test, whatever it returns
    "helper that always returns False": "False and ({p})",
    "helper that always returns True": "True",
    "helper with the real test": "{p}",
    "helper that tests only long inputs": "len(v) > 9 and ({p})",
}
REGEX_POSITIVE = "re.search(r'\\.env|rm -rf|git push', {x})"
REGEX_MISSES = {
    "re.match": "re.match(r'\\.env|rm -rf|git push', {x})",
    "re.fullmatch": "re.fullmatch(r'\\.env|rm -rf|git push', {x})",
    "anchored with ^": "re.search(r'^(\\.env|rm -rf|git push)', {x})",
    "anchored with $": "re.search(r'(\\.env|rm -rf|git push)$', {x})",
    "compiled pattern with .match": "PATTERN.match({x})",
    "pattern built at run time": "re.search(PATTERN_TEXT, {x})",
}
REGEX_MODULE = "PATTERN = re.compile(r'\\.env|rm -rf|git push')\nPATTERN_TEXT = '|'.join(['\\\\.env', 'rm -rf', 'git push'])\n"


class Round3NearMisses(unittest.TestCase):
    """One change to each kind's canonical positive: no credit. The positives keep theirs."""

    def check(self, kind, label, files, want=0):
        with self.subTest(kind=kind.name, case=label):
            pts, st = score(files)
            self.assertEqual(pts, want, (st, files["agent.py"]))

    def test_for_versus_while_and_other_blocks_earn_nothing(self):
        for kind in KINDS:
            for label, structure in LOOP_MISSES.items():
                self.check(kind, label, {"agent.py": kind.source(structure=structure)})

    def test_a_loop_local_exit_is_not_a_function_level_refusal(self):
        for kind in KINDS:
            self.check(kind, "function-level refusal (positive)", {"agent.py": kind.source()}, want=8)
            for label, exit_ in LOOP_LOCAL_EXITS.items():
                self.check(kind, f"loop-local {label}", {"agent.py": kind.source(structure="    for _ in [1]:\n{refusal}",
                                                                                     refuse=exit_)})

    def test_the_right_input_earns_credit_and_the_wrong_one_does_not(self):
        for kind in KINDS:
            self.check(kind, "the tool's own input (positive)", {"agent.py": kind.source()}, want=8)
            self.check(kind, "another parameter or field", {"agent.py": kind.source(**WRONG_VALUE[kind.name])})

    def test_changing_the_input_before_the_test_earns_nothing(self):
        for kind in KINDS:
            self.check(kind, "input changed or rebound", {"agent.py": kind.source(**REBIND[kind.name])})

    def test_readable_helpers_are_not_canonical(self):
        for kind in KINDS:
            for label, body in HELPERS.items():
                helper = f"def blocked(v):\n    return {body.format(p=P.format(x='v'))}\n"
                self.check(kind, label, {"agent.py": kind.source(cond="blocked({x})", module=helper)})

    def test_anchored_regexes_earn_nothing_and_unanchored_search_earns_credit(self):
        for kind in KINDS:
            self.check(kind, "re.search (positive)", {"agent.py": kind.source(cond=REGEX_POSITIVE, module=REGEX_MODULE)}, want=8)
            for label, cond in REGEX_MISSES.items():
                self.check(kind, label, {"agent.py": kind.source(cond=cond, module=REGEX_MODULE)})

    def test_the_sdk_field_must_be_the_one_the_tool_executes(self):
        kind = next(k for k in KINDS if k.name.startswith("PreToolUse"))
        for field, want in (("command", 8), ("file_path", 0), ("description", 0)):
            header = f"async def gate(data, tool_use_id, context):\n    command = data.get('tool_input', {{}}).get('{field}', '')\n"
            self.check(kind, f"field {field}", {"agent.py": kind.source(header=header)}, want=want)


class ReachNearMisses(unittest.TestCase):
    """A guarded tool keeps its credit; one extra call it cannot see past takes it away."""
    BASE = ("import re, subprocess\nfrom agents import Agent\n{module}def run(command):\n"
            "    if '.env' in command or 'rm -rf' in command or 'git push' in command:\n        return 'denied'\n"
            "{extra}    return subprocess.run(command, shell=True).returncode\nagent = Agent(name='w', tools=[run])\n")

    def test_zero_input_helpers_are_followed(self):
        self.assertEqual(score({"agent.py": self.BASE.format(module="", extra="")})[0], 8)
        cases = {
            "fixed push in a zero-input helper": ("def push():\n    return subprocess.run('git push', shell=True)\n", "    push()\n"),
            "two helpers deep": ("def a():\n    return subprocess.run('git push', shell=True)\ndef b():\n    return a()\n", "    b()\n"),
            "fixed delete in a helper": ("import shutil\ndef wipe():\n    shutil.rmtree('/constructed')\n", "    wipe()\n"),
            "fixed secret read in a helper": ("from pathlib import Path\ndef peek():\n    return Path('.env').read_text()\n", "    peek()\n"),
            "an object the audit cannot follow": ("import external_service\n", "    external_service.client.reset()\n"),
        }
        for label, (module, extra) in cases.items():
            with self.subTest(case=label):
                pts, st = score({"agent.py": self.BASE.format(module=module, extra=extra)})
                self.assertLess(pts, 8, (st, label))

    def test_a_refusal_reaches_a_helper_only_through_the_same_name(self):
        helper = "def execute(cmd):\n    return subprocess.run(cmd, shell=True).returncode\n"
        good = self.BASE.format(module=helper, extra="").replace("    return subprocess.run(command, shell=True).returncode\nagent",
                                                                 "    return execute(command)\nagent")
        self.assertEqual(score({"agent.py": good})[0], 8)
        for label, call in {"converted": "execute(command.strip())", "another value": "execute('git status')",
                            "wrapped": "execute(f'{command}')"}.items():
            with self.subTest(case=label):
                self.assertEqual(score({"agent.py": good.replace("execute(command)", call)})[0], 0)
        rebinding_helper = helper.replace("    return", "    cmd = cmd + ' '\n    return")
        self.assertEqual(score({"agent.py": good.replace(helper, rebinding_helper)})[0], 0)


class McpMapNearMisses(unittest.TestCase):
    SDK = "from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, tool\n{defs}opts = ClaudeAgentOptions(tools=[], allowed_tools={allowed}, mcp_servers={servers})\n"
    NARROW = "@tool('status', 'fixed', {})\ndef status(args):\n    return 'ok'\nprod = create_sdk_mcp_server(name='prod', tools=[status])\n"

    def test_unknown_maps_are_unresolved_whatever_is_approved(self):
        maps = {"imported": ("from servers import SERVERS\n", "SERVERS"),
                "built by a call": ("from servers import make_servers\n", "make_servers()"),
                "an external server value": ("from servers import PROD\n", "{'prod': PROD}"),
                "a stdio server dict": ("", "{'prod': {'type': 'stdio', 'command': 'prod-mcp'}}")}
        for allowed in ("['mcp__prod__*']", "['mcp__prod']", "['mcp__prod__execute']", "[]"):
            for label, (defs, servers) in maps.items():
                with self.subTest(allowed=allowed, map=label):
                    pts, st = score({"agent.py": self.SDK.format(defs=defs, allowed=allowed, servers=servers)})
                    self.assertEqual(set(st.values()), {"UNRESOLVED"}, st)

    def test_a_known_narrow_map_keeps_its_credit_and_an_unlisted_wildcard_does_not(self):
        self.assertEqual(score({"agent.py": self.SDK.format(defs=self.NARROW, allowed="['mcp__prod__*']",
                                                           servers="{'prod': prod}")})[0], 8)
        pts, st = score({"agent.py": self.SDK.format(defs=self.NARROW, allowed="['mcp__other__*']", servers="{'prod': prod}")})
        self.assertEqual(set(st.values()), {"UNRESOLVED"}, st)


class SymlinkNearMisses(unittest.TestCase):
    """Directory versus file links, in the tree and out of it: only what resolves inside the audited root is read."""
    SETTINGS = json.dumps({"permissions": {"ask": ["Bash(*)", "WebFetch", "Write", "Edit"],
                                           "deny": ["MultiEdit", "NotebookEdit", "WebSearch", "Read", "Grep", "Glob"]}})
    POLICY = ("def gate(tool, args, tool_context):\n    if '.env' in str(args) or 'rm -rf' in str(args) or 'git push' in str(args):\n"
              "        return {'error': 'denied'}\n    return None\n")
    AGENT = ("import subprocess\nfrom google.adk.agents import Agent\nfrom {mod} import gate\n" + SHELL_TOOL +
             "agent = Agent(name='w', tools=[run], before_tool_callback=gate)\n")

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.out = self.base / "outside"
        (self.out / "claude").mkdir(parents=True)
        (self.out / "claude" / "settings.json").write_text(self.SETTINGS)
        (self.out / "policy.py").write_text(self.POLICY)
        (self.out / "pkg").mkdir()
        (self.out / "pkg" / "policy.py").write_text(self.POLICY)

    def tearDown(self):
        shutil.rmtree(self.base)

    def repo(self, name):
        d = self.base / name
        d.mkdir()
        return d

    def test_settings_through_file_and_directory_links(self):
        d = self.repo("plain")
        (d / ".claude").mkdir()
        (d / ".claude" / "settings.json").write_text(self.SETTINGS)
        self.assertEqual(points(audit(d)), 8)                                        # positive
        d = self.repo("dir_in")
        (d / "real_claude").mkdir()
        (d / "real_claude" / "settings.json").write_text(self.SETTINGS)
        (d / ".claude").symlink_to("real_claude", target_is_directory=True)
        self.assertEqual(points(audit(d)), 8)                                        # an in-tree directory link
        d = self.repo("file_in")
        (d / ".claude").mkdir()
        (d / "settings.real.json").write_text(self.SETTINGS)
        (d / ".claude" / "settings.json").symlink_to("../settings.real.json")
        self.assertEqual(points(audit(d)), 8)                                        # an in-tree file link
        d = self.repo("dir_out")
        (d / ".claude").symlink_to(self.out / "claude", target_is_directory=True)
        self.assertEqual(points(audit(d)), 0)
        d = self.repo("file_out")
        (d / ".claude").mkdir()
        (d / ".claude" / "settings.json").symlink_to(self.out / "claude" / "settings.json")
        self.assertEqual(points(audit(d)), 0)

    def test_guard_modules_through_file_and_directory_links(self):
        d = self.repo("plain_mod")
        (d / "policy.py").write_text(self.POLICY)
        (d / "agent.py").write_text(self.AGENT.format(mod="policy"))
        self.assertEqual(points(audit(d)), 8)                                        # positive
        d = self.repo("file_out_mod")
        (d / "policy.py").symlink_to(self.out / "policy.py")
        (d / "agent.py").write_text(self.AGENT.format(mod="policy"))
        self.assertEqual(points(audit(d)), 0)
        d = self.repo("dir_out_mod")
        (d / "pkg").symlink_to(self.out / "pkg", target_is_directory=True)
        (d / "agent.py").write_text(self.AGENT.format(mod="pkg.policy"))
        self.assertEqual(points(audit(d)), 0)


if __name__ == "__main__":
    unittest.main()
