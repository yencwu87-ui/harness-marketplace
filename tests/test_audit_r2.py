"""Codex round-2 findings on 1.4.2 (R2-01 to R2-05), written as the invariant the audit must hold:
credit only what is proven. A guard earns points only when it is explicit, unconditional and attached to the scored
agent or tool, and the audit can prove that from the files; anything narrower, conditional, attached elsewhere or
unprovable earns nothing. Reach analysis never reports a capability absent that a tool invokes.

Fixtures under tests/fixtures/codex_r2 come from Codex's round-2 review of 1.4.2 (see its README).
R2-06 (the SDK search tool and symlinks) is in test_live_safety.py, beside the other search-tool tests.
"""
import json
import unittest

from test_audit_fairness import GUARD, Repo, audit, guards, points, ROOT

FIX = ROOT / "tests/fixtures/codex_r2"
OAI = "import re, subprocess\nfrom agents import Agent, function_tool\n"
SECRET = 'SECRET = re.compile(r"(\\.env|\\.pem|\\.key|\\.ssh|\\.aws)")\n'


def statuses(rep):
    return tuple(guards(rep)[c]["status"] for c in GUARD)


class R2_01_RefusalMeaning(unittest.TestCase):
    """A refusal counts only when it controls the capability on every path and its predicate covers the class."""

    def test_codex_fixtures_lose_unsupported_credit(self):
        for name in ("nested_guard", "and_guard", "conditional_hook"):
            with self.subTest(fixture=name):
                rep = audit(FIX / name)
                self.assertEqual(points(rep), 0, guards(rep))
                self.assertNotIn("VERIFIED", statuses(rep))

    def test_or_earns_and_and_does_not(self):
        body = "def run(command):\n    if {cond}:\n        return 'denied'\n    return subprocess.run(command, shell=True).returncode\n" \
               "agent = Agent(name='w', tools=[run])\n"
        either = "'.env' in command or 'rm -rf' in command"
        both = "'.env' in command and 'rm -rf' in command"
        with Repo({"agent.py": OAI + body.format(cond=either)}) as d:
            self.assertEqual(points(audit(d)), 8)
        with Repo({"agent.py": OAI + body.format(cond=both)}) as d:
            self.assertEqual(points(audit(d)), 0)

    def test_nested_guard_counts_only_when_its_enclosing_condition_always_holds(self):
        body = ("ENFORCE = {flag}\ndef run(command{param}):\n    if {outer}:\n"
                "        if '.env' in command or 'rm -rf' in command or 'git push' in command:\n            return 'denied'\n"
                "    return subprocess.run(command, shell=True).returncode\nagent = Agent(name='w', tools=[run])\n")
        # 1.4.4: a refusal nested under any `if` is not a canonical form (F1), even when the condition is a module
        # constant that is always True. 1.4.3 credited that case (8); it is now a documented false negative.
        cases = {"module constant True": (dict(flag="True", param="", outer="ENFORCE"), 0),
                 "module constant False": (dict(flag="False", param="", outer="ENFORCE"), 0),
                 "parameter the model sets, default True": (dict(flag="True", param=", enforce=True", outer="enforce"), 0),
                 "parameter default False (Codex)": (dict(flag="True", param=", enforce=False", outer="enforce"), 0)}
        for name, (fmt, want) in cases.items():
            with self.subTest(case=name), Repo({"agent.py": OAI + body.format(**fmt)}) as d:
                self.assertEqual(points(audit(d)), want, guards(audit(d)))

    def test_hook_restricted_to_another_tool_gives_nothing_and_to_this_tool_gives_credit(self):
        src = ("from google.adk.agents import Agent\nimport subprocess, re\n"
               "def gate(tool, args, tool_context):\n    if tool.name == '{name}':\n"
               "        if re.search(r'.env|.pem|.key', str(args)) or 'rm -rf' in str(args) or 'git push' in str(args):\n"
               "            return {{'error': 'denied'}}\n    return None\n"
               "def unsafe(command):\n    return subprocess.run(command, shell=True).returncode\n"
               "agent = Agent(name='w', tools=[unsafe], before_tool_callback=gate)\n")
        with Repo({"agent.py": src.format(name="safe")}) as d:
            self.assertEqual(points(audit(d)), 0)
        with Repo({"agent.py": src.format(name="unsafe")}) as d:
            self.assertEqual(points(audit(d)), 8)

    def test_combining_hook_conditions_keeps_their_restrictions(self):
        """One condition refuses secrets only for 'safe', another destructive commands for every tool:
        'unsafe' is covered for G3 only."""
        src = ("from google.adk.agents import Agent\nimport subprocess, re\n"
               "def gate(tool, args, tool_context):\n"
               "    if tool.name == 'safe' and re.search(r'.env|.pem|.key', str(args)):\n        return {'error': 'denied'}\n"
               "    if 'rm -rf' in str(args) or 'git push' in str(args):\n        return {'error': 'denied'}\n    return None\n"
               "def unsafe(command):\n    return subprocess.run(command, shell=True).returncode\n"
               "agent = Agent(name='w', tools=[unsafe], before_tool_callback=gate)\n")
        with Repo({"agent.py": src}) as d:
            g = guards(audit(d))
            self.assertNotEqual(g["G2"]["status"], "VERIFIED", g)
            self.assertEqual(g["G3"]["status"], "VERIFIED", g)

    def test_a_genuine_unconditional_refusal_keeps_its_points(self):
        self.assertEqual(points(audit(ROOT / "tests/fixtures/codex_r1/inline_real_guard")), 8)


class R2_02_CrewAITask(unittest.TestCase):
    def test_a_task_for_another_agent_gives_no_credit(self):
        rep = audit(FIX / "crewai_task_pooling")
        self.assertEqual(points(rep), 0, guards(rep))
        self.assertNotIn("guarded by human_input", json.dumps(guards(rep)))

    def test_human_input_reviews_output_after_the_tools_ran_so_it_is_no_per_call_approval(self):
        src = (FIX / "crewai_task_pooling" / "agent.py").read_text().replace("agent=safe, human_input", "agent=unsafe, human_input")
        with Repo({"agent.py": src}) as d:
            rep = audit(d)
            self.assertEqual(points(rep), 0, guards(rep))
            self.assertIn("human_input", guards(rep)["G1"]["evidence"])     # the reason is named

    def test_a_before_tool_call_hook_still_earns_credit(self):
        src = ("import re, subprocess\nfrom crewai import Agent\nfrom crewai.hooks import register_before_tool_call_hook\n" + SECRET +
               "def gate(ctx):\n    if SECRET.search(str(ctx.tool_input)) or 'rm -rf' in str(ctx.tool_input):\n        return False\n"
               "    return None\nregister_before_tool_call_hook(gate)\n"
               "def run(command):\n    return subprocess.run(command, shell=True).returncode\n"
               "unsafe = Agent(role='unsafe', goal='g', backstory='b', tools=[run])\n")
        with Repo({"agent.py": src}) as d:
            self.assertEqual(points(audit(d)), 8)


class R2_03_Reach(unittest.TestCase):
    def test_codex_fixtures_do_not_assert_absence(self):
        for name in ("bound_method", "path_open", "fixed_command"):
            with self.subTest(fixture=name):
                rep = audit(FIX / name)
                self.assertLess(points(rep), 8, guards(rep))

    def test_local_module_alias_scores_like_the_direct_call(self):
        direct = "def run(command):\n    return subprocess.run(command, shell=True).returncode\n"
        alias = "def run(command):\n    runner = subprocess\n    return runner.run(command, shell=True).returncode\n"
        alias2 = "runner = subprocess\ndef run(command):\n    return runner.run(command, shell=True).returncode\n"
        alias3 = "def run(command):\n    go = subprocess.run\n    return go(command, shell=True).returncode\n"
        got = {}
        for name, body in {"direct": direct, "local": alias, "module": alias2, "function": alias3}.items():
            with Repo({"agent.py": OAI + body + "agent = Agent(name='w', tools=[run])\n"}) as d:
                got[name] = statuses(audit(d))
        self.assertEqual(set(got.values()), {("MISSING", "MISSING", "MISSING")}, got)

    def test_path_open_scores_like_open(self):
        tail = "agent = Agent(name='w', tools=[read])\n"
        a = OAI + "def read(path):\n    with open(path) as f:\n        return f.read()\n" + tail
        b = OAI + "from pathlib import Path\ndef read(path):\n    with Path(path).open() as f:\n        return f.read()\n" + tail
        with Repo({"agent.py": a}) as da, Repo({"agent.py": b}) as db:
            ra, rb = audit(da), audit(db)
            self.assertEqual(statuses(ra), statuses(rb))
            self.assertEqual(guards(rb)["G2"]["status"], "MISSING", guards(rb))

    def test_a_fixed_destructive_command_still_needs_a_gate(self):
        rep = audit(FIX / "fixed_command")
        g = guards(rep)
        self.assertEqual(g["G3"]["status"], "MISSING", g)
        self.assertNotIn("no tool can run commands", g["G3"]["evidence"])
        self.assertNotIn("no shell", g["G1"]["evidence"])

    def test_a_benign_fixed_command_is_reported_not_hidden(self):
        src = OAI + "def status():\n    return subprocess.run(['git', 'status', '--short'], capture_output=True).stdout\n" \
                    "agent = Agent(name='w', tools=[status])\n"
        with Repo({"agent.py": src}) as d:
            rep = audit(d)
            self.assertEqual(points(rep), 8, guards(rep))
            self.assertIn("git status --short", guards(rep)["G1"]["evidence"])

    def test_a_call_through_getattr_is_unresolved_not_absent(self):
        src = OAI + "def run(command):\n    return getattr(subprocess, 'run')(command, shell=True).returncode\n" \
                    "agent = Agent(name='w', tools=[run])\n"
        with Repo({"agent.py": src}) as d:
            self.assertNotIn("VERIFIED", statuses(audit(d)))


class R2_04_SdkMcpBinding(unittest.TestCase):
    SRC = ("from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, tool\nimport subprocess\n"
           "{first}\n{second}\nserver = create_sdk_mcp_server(name='prod', tools=[{attached}])\n"
           "opts = ClaudeAgentOptions(tools=[], allowed_tools=['mcp__prod__execute'], mcp_servers={{'prod': server}})\n")
    INNOCENT = "@tool('execute', 'safe fixed result', {})\ndef innocent(args):\n    return 'fixed'\n"
    UNSAFE = "@tool('execute', 'run a command', {'command': str})\ndef unsafe(args):\n    return subprocess.run(args['command'], shell=True).returncode\n"

    def test_codex_fixture_loses_credit(self):
        self.assertEqual(points(audit(FIX / "sdk_mcp_wrong_server")), 0)

    def test_the_attached_implementation_decides_in_any_order(self):
        for first, second in ((self.INNOCENT, self.UNSAFE), (self.UNSAFE, self.INNOCENT)):
            with self.subTest(order=first[:30]):
                with Repo({"agent.py": self.SRC.format(first=first, second=second, attached="unsafe")}) as d:
                    self.assertEqual(points(audit(d)), 0)
                with Repo({"agent.py": self.SRC.format(first=first, second=second, attached="innocent")}) as d:
                    self.assertEqual(points(audit(d)), 8, guards(audit(d)))

    def test_same_name_on_an_unconfigured_server_does_not_count(self):
        src = self.SRC.format(first=self.INNOCENT, second=self.UNSAFE, attached="innocent") + \
            "other = create_sdk_mcp_server(name='other', tools=[unsafe])\n"
        with Repo({"agent.py": src}) as d:
            self.assertEqual(points(audit(d)), 8)

    def test_an_unreadable_server_binding_is_unresolved(self):
        src = ("from claude_agent_sdk import ClaudeAgentOptions\nfrom servers import SERVERS\n"
               "opts = ClaudeAgentOptions(tools=[], allowed_tools=['mcp__prod__execute'], mcp_servers=SERVERS)\n")
        with Repo({"agent.py": src}) as d:
            self.assertEqual(set(statuses(audit(d))), {"UNRESOLVED"})


class R2_05_ClaudeScopedAsk(unittest.TestCase):
    def settings(self, perms, sandbox=False):
        data = {"permissions": perms}
        if sandbox:
            data["sandbox"] = {"enabled": True, "autoAllowBashIfSandboxed": True}
        return Repo({".claude/settings.json": json.dumps(data)})

    OTHERS = ["Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "Read", "Grep", "Glob"]

    def test_codex_fixture_loses_credit(self):
        rep = audit(FIX / "partial_claude_ask")
        self.assertNotIn("VERIFIED", statuses(rep), guards(rep))

    def test_ask_for_the_whole_tool_still_counts(self):
        with self.settings({"allow": ["Bash(*)"], "ask": ["Bash(*)"], "deny": self.OTHERS}) as d:
            self.assertEqual(points(audit(d)), 8)

    def test_overlapping_allow_and_scoped_ask_covers_only_its_scope(self):
        with self.settings({"allow": ["Bash(*)"], "ask": ["Bash(git push *)", "Bash(rm -rf *)"], "deny": self.OTHERS}) as d:
            g = guards(audit(d))
            self.assertEqual(g["G3"]["status"], "VERIFIED", g)
            self.assertNotEqual(g["G2"]["status"], "VERIFIED", g)

    def test_scoped_file_tool_ask_does_not_gate_the_whole_tool(self):
        others = [t for t in self.OTHERS if t not in ("Write",)] + ["Bash"]
        with self.settings({"allow": ["Write"], "ask": ["Write(./src/**)"], "deny": others}) as d:
            g = guards(audit(d))
            self.assertNotEqual(g["G3"]["status"], "VERIFIED", g)
            self.assertNotEqual(g["G1"]["status"], "VERIFIED", g)


if __name__ == "__main__":
    unittest.main()
