"""Codex round-3 findings on 1.4.3 (R3-01 to R3-07), written as the invariant the audit must hold from 1.4.4 on:
credit only canonical guard forms. A code refusal earns points only in the written forms listed in the audit
(`CANONICAL_FORMS`, printed by `audit.py --canonical-forms`); every other shape is UNRESOLVED with a named reason.
Reach fails closed, configuration the audit cannot read is never "no tools", every rule source uses one coverage
standard, sandbox credit needs a sandbox without escapes, and every file the audit reads is inside the audited root.

Fixtures under tests/fixtures/codex_r3 come from Codex's round-3 review of 1.4.3 (see its README).
"""
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import GUARD, Repo, audit, guards, load_audit, points, ROOT

FIX = ROOT / "tests/fixtures/codex_r3"
KIT_GUARD = ROOT / "kit/shared/kit_guard.py"
OAI = "import re, subprocess\nfrom agents import Agent, function_tool\n"
COND = "'.env' in command or 'rm -rf' in command or 'git push' in command"
SHELL = "    return subprocess.run(command, shell=True).returncode\n"
WIRE = "agent = Agent(name='w', tools=[run])\n"


def statuses(rep):
    return tuple(guards(rep)[c]["status"] for c in GUARD)


def tool(body, header="def run(command):\n", tail=SHELL, extra=""):
    return {"agent.py": OAI + extra + header + body + tail + WIRE}


def score(files):
    with Repo(files) as d:
        rep = audit(d)
        return points(rep), statuses(rep), guards(rep)


class R3_01_LoopLocalRefusals(unittest.TestCase):
    """A refusal inside a loop does not control a capability after it: not canonical, no credit."""

    def test_codex_fixtures_lose_unsupported_credit(self):
        for name in ("empty_for", "continue_for"):
            with self.subTest(fixture=name):
                rep = audit(FIX / name)
                self.assertEqual(points(rep), 0, guards(rep))
                self.assertNotIn("VERIFIED", statuses(rep))

    def test_loop_shapes_earn_nothing_and_the_top_level_refusal_keeps_its_points(self):
        refuse = f"        if {COND}:\n            {{exit}}\n"
        cases = {
            "empty for, return": "    for _ in []:\n" + refuse.format(exit="return 'denied'"),
            "one-iteration for, continue": "    for _ in [1]:\n" + refuse.format(exit="continue"),
            "one-iteration for, break": "    for _ in [1]:\n" + refuse.format(exit="break"),
            "for over the input, return": "    for part in [command]:\n" + refuse.format(exit="return 'denied'"),
            "conditional iteration": "    for _ in ([1] if len(command) > 3 else []):\n" + refuse.format(exit="return 'denied'"),
            "while True with break": "    while True:\n" + refuse.format(exit="return 'denied'") + "        break\n",
            "with block": "    with open('/dev/null') as _f:\n" + refuse.format(exit="return 'denied'"),
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                pts, st, g = score(tool(body))
                self.assertEqual(pts, 0, (st, body))
                self.assertNotIn("VERIFIED", st, body)
        pts, st, g = score(tool(f"    if {COND}:\n        return 'denied'\n"))
        self.assertEqual(pts, 8, g)

    def test_a_hook_refusal_inside_a_loop_earns_nothing(self):
        src = ("from google.adk.agents import Agent\nimport subprocess\n"
               "def gate(tool, args, tool_context):\n    for _ in []:\n"
               "        if '.env' in str(args) or 'rm -rf' in str(args) or 'git push' in str(args):\n"
               "            return {'error': 'denied'}\n    return None\n"
               "def run(command):\n" + SHELL + "agent = Agent(name='w', tools=[run], before_tool_callback=gate)\n")
        self.assertEqual(score({"agent.py": src})[0], 0)
        self.assertEqual(score({"agent.py": src.replace("    for _ in []:\n        if", "    if").replace(
            "\n            return {'error'", "\n        return {'error'")})[0], 8)


class R3_02_PredicateBindsTheExecutedInput(unittest.TestCase):
    """The tested value must be the very parameter the capability receives, unmodified; the predicate must be one of
    the canonical forms; a regex must find the keyword wherever it appears."""

    def test_codex_fixtures_lose_unsupported_credit(self):
        for name in ("wrong_parameter", "overwritten_input", "helper_flag", "regex_match"):
            with self.subTest(fixture=name):
                rep = audit(FIX / name)
                self.assertEqual(points(rep), 0, guards(rep))
                self.assertNotIn("VERIFIED", statuses(rep))

    def test_correct_versus_wrong_parameter(self):
        right = tool(f"    if {COND}:\n        return 'denied'\n", header="def run(command, label=''):\n")
        wrong = tool(f"    if {COND.replace('command', 'label')}:\n        return 'denied'\n", header="def run(command, label=''):\n")
        self.assertEqual(score(right)[0], 8)
        self.assertEqual(score(wrong)[0], 0)

    def test_rebinding_before_or_after_the_check_earns_nothing(self):
        refusal = f"    if {COND}:\n        return 'denied'\n"
        cases = {
            "captured, then overwritten (Codex)": ("    original = command\n    command = ''\n" + refusal,
                                                    "    return subprocess.run(original, shell=True).returncode\n"),
            "rebound after the check": (refusal + "    command = command + ' --quiet'\n", SHELL),
            "stripped before the call": (refusal, "    return subprocess.run(command.strip(), shell=True).returncode\n"),
            "sliced into the call": (refusal, "    return subprocess.run(command[1:], shell=True).returncode\n"),
            "wrapped in a list": (refusal, "    return subprocess.run(['sh', '-c', command]).returncode\n"),
            "augmented": (refusal + "    command += ''\n", SHELL),
        }
        for name, (body, tail) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(score(tool(body, tail=tail))[0], 0, body + tail)

    def test_helper_predicates_are_not_read_by_text(self):
        helper = "def blocked(command):\n    return {ret}\n"
        refusal = "    if blocked(command):\n        return 'denied'\n"
        for name, ret in {"always False (Codex)": f"False and ({COND})", "always True": "True",
                          "the real test": COND, "conditional": f"len(command) > 9 and ({COND})"}.items():
            with self.subTest(helper=name):
                self.assertEqual(score(tool(refusal, extra=helper.format(ret=ret)))[0], 0)

    def test_the_kit_guard_helper_earns_credit_only_unmodified(self):
        self.assertTrue(KIT_GUARD.is_file(), "kit/shared/kit_guard.py is the kit's shipped guard helper")
        helper = KIT_GUARD.read_text()
        src = OAI + "import kit_guard\ndef run(command):\n    if kit_guard.refuses(command):\n        return 'denied'\n" + SHELL + WIRE
        src_from = src.replace("import kit_guard\n", "from kit_guard import refuses\n").replace("kit_guard.refuses(", "refuses(")
        self.assertEqual(score({"agent.py": src, "kit_guard.py": helper})[0], 8)
        self.assertEqual(score({"agent.py": src_from, "kit_guard.py": helper})[0], 8)
        edited = helper.replace("return secret(value) or destructive(value)", "return False", 1)
        self.assertNotEqual(edited, helper)
        self.assertEqual(score({"agent.py": src, "kit_guard.py": edited})[0], 0)
        self.assertEqual(score({"agent.py": src})[0], 0)                       # helper missing: unreadable

    def test_regex_must_find_the_keyword_anywhere(self):
        refusal = "    if {call}:\n        return 'denied'\n"
        good = {"re.search": "re.search(r'\\.env|rm -rf|git push', command)",
                "re.search, word-bounded": "re.search(r'\\.env\\b|\\brm\\s+-rf\\b|\\bgit\\s+push\\b', command)",
                "compiled module constant": "PATTERN.search(command)"}
        bad = {"re.match (Codex)": "re.match(r'\\.env|rm -rf|git push', command)",
               "re.fullmatch": "re.fullmatch(r'\\.env|rm -rf|git push', command)",
               "anchored at the start": "re.search(r'^(\\.env|rm -rf|git push)', command)",
               "anchored at the end": "re.search(r'(\\.env|rm -rf|git push)$', command)",
               "re.match with .* (misses a second line)": "re.match(r'.*(\\.env|rm -rf|git push)', command)",
               "compiled .match": "PATTERN.match(command)",
               "pattern from a variable": "re.search(PATTERN_TEXT, command)"}
        extra = "PATTERN = re.compile(r'\\.env|rm -rf|git push')\nPATTERN_TEXT = ''.join(['\\\\.env|rm -rf|git push'])\n"
        for name, call in good.items():
            with self.subTest(good=name):
                self.assertEqual(score(tool(refusal.format(call=call), extra=extra))[0], 8)
        for name, call in bad.items():
            with self.subTest(bad=name):
                self.assertEqual(score(tool(refusal.format(call=call), extra=extra))[0], 0)


class R3_03_ReachFailsClosed(unittest.TestCase):
    def test_codex_fixtures_report_the_capability(self):
        for name, cid in (("noarg_helper", "G3"), ("fixed_path_read", "G2"), ("fixed_rmtree", "G3"), ("fixed_unknown_object", "G3")):
            with self.subTest(fixture=name):
                g = guards(audit(FIX / name))
                self.assertNotEqual(g[cid]["status"], "VERIFIED", g)
        g = guards(audit(FIX / "fixed_unknown_object"))
        self.assertEqual(g["G3"]["status"], "UNRESOLVED", g)

    def test_direct_and_helper_fixed_push_score_the_same(self):
        self.assertEqual(statuses(audit(FIX / "helper_direct")), statuses(audit(FIX / "noarg_helper")))
        self.assertEqual(points(audit(FIX / "noarg_helper")), 3)

    def test_inherently_destructive_operations_need_a_gate_whatever_their_target(self):
        ops = {"shutil.rmtree": "import shutil\ndef run():\n    shutil.rmtree('/constructed/work')\n    return 'ok'\n",
               "os.remove": "import os\ndef run():\n    os.remove('/constructed/file')\n    return 'ok'\n",
               "os.unlink": "import os\ndef run():\n    os.unlink('/constructed/file')\n    return 'ok'\n",
               "Path.unlink": "from pathlib import Path\ndef run():\n    Path('/constructed/file').unlink()\n    return 'ok'\n",
               "rm in a fixed shell command": "def run():\n    return subprocess.run(['rm', '/constructed/file']).returncode\n",
               "git reset --hard": "def run():\n    return subprocess.run('git reset --hard HEAD~1', shell=True).returncode\n"}
        for name, body in ops.items():
            with self.subTest(op=name):
                pts, st, g = score({"agent.py": OAI + body + WIRE})
                self.assertNotEqual(st[2], "VERIFIED", g)

    def test_fixed_secret_reads_are_reads(self):
        for name, body in {"Path(...).read_text()": "from pathlib import Path\ndef run():\n    return Path('.env').read_text()\n",
                           "open(...)": "def run():\n    with open('.aws/credentials') as f:\n        return f.read()\n",
                           "Path(...).open()": "from pathlib import Path\ndef run():\n    with Path('id_rsa').open() as f:\n        return f.read()\n"}.items():
            with self.subTest(read=name):
                pts, st, g = score({"agent.py": OAI + body + WIRE})
                self.assertNotEqual(st[1], "VERIFIED", g)

    def test_a_benign_fixed_read_or_command_stays_narrow(self):
        for body in ("from pathlib import Path\ndef run():\n    return Path('README.md').read_text()\n",
                     "def run():\n    return subprocess.run(['git', 'status', '--short'], capture_output=True).stdout\n"):
            with self.subTest(body=body):
                self.assertEqual(score({"agent.py": OAI + body + WIRE})[0], 8)

    def test_calls_without_tool_input_are_followed(self):
        unknown = OAI + "import external_service\ndef run():\n    external_service.reset()\n    return 'ok'\n" + WIRE
        self.assertEqual(score({"agent.py": unknown})[1], ("UNRESOLVED",) * 3)
        deep = OAI + "def a():\n    return subprocess.run('git push', shell=True)\ndef b():\n    return a()\ndef run():\n    return b()\n" + WIRE
        self.assertNotEqual(score({"agent.py": deep})[1][2], "VERIFIED")


class R3_04_UnreadableMcpMap(unittest.TestCase):
    SDK = "from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, tool\nimport subprocess\n"

    def test_codex_fixtures_are_unresolved_with_the_map_reason(self):
        for name in ("sdk_unknown_servers_wildcard", "sdk_unknown_servers_no_allow"):
            with self.subTest(fixture=name):
                g = guards(audit(FIX / name))
                self.assertEqual({x["status"] for x in g.values()}, {"UNRESOLVED"}, g)
                self.assertIn("mcp_servers", g["G3"]["evidence"])
                self.assertNotIn("no tools", g["G3"]["evidence"])

    def test_server_wide_approval_with_an_unknown_map_is_unresolved(self):
        for allowed in ("['mcp__prod']", "['mcp__prod__*']", "['mcp__prod__execute']", "[]"):
            src = self.SDK + f"from servers import SERVERS\nopts = ClaudeAgentOptions(tools=[], allowed_tools={allowed}, mcp_servers=SERVERS)\n"
            with self.subTest(allowed=allowed):
                self.assertEqual(set(score({"agent.py": src})[1]), {"UNRESOLVED"})

    def test_known_maps_are_scored(self):
        narrow = "@tool('status', 'fixed', {})\ndef status(args):\n    return 'ok'\n"
        broad = "@tool('execute', 'run', {'command': str})\ndef execute(args):\n    return subprocess.run(args['command'], shell=True).returncode\n"
        base = "opts = ClaudeAgentOptions(tools=[], allowed_tools=['mcp__prod__*'], mcp_servers={servers})\n"
        cases = {"known narrow": (narrow + "prod = create_sdk_mcp_server(name='prod', tools=[status])\n", "{'prod': prod}", 8),
                 "known broad": (broad + "prod = create_sdk_mcp_server(name='prod', tools=[execute])\n", "{'prod': prod}", 0),
                 "known empty map, wildcard for a server not in it": ("", "{}", None)}
        for name, (defs, servers, want) in cases.items():
            with self.subTest(case=name):
                pts, st, g = score({"agent.py": self.SDK + defs + base.format(servers=servers)})
                if want is None:
                    self.assertEqual(set(st), {"UNRESOLVED"}, g)
                else:
                    self.assertEqual(pts, want, g)


class R3_05_SdkRuleScope(unittest.TestCase):
    """SDK disallowed_tools use exactly the native Claude Code standard: a scoped rule covers only its scope."""

    def sdk(self, deny):
        return {"agent.py": "from claude_agent_sdk import ClaudeAgentOptions\n"
                            f"opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], disallowed_tools={deny!r})\n"}

    def native(self, deny):
        others = ["Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "Read", "Grep", "Glob"]
        return {".claude/settings.json": json.dumps({"permissions": {"allow": ["Bash(*)"], "deny": others + deny}})}

    def test_codex_fixture_loses_scoped_credit(self):
        g = guards(audit(FIX / "sdk_scoped_deny"))
        self.assertNotEqual(g["G2"]["status"], "VERIFIED", g)
        self.assertNotEqual(g["G3"]["status"], "VERIFIED", g)

    def test_identical_rules_score_the_same_on_both_rule_sources(self):
        for deny in (["Bash(cat *.env*)", "Bash(git push origin main)"], ["Bash(git push *)", "Bash(rm -rf *)"],
                     ["Bash(*.env*)", "Bash(git push *)"], ["Bash(git push)"], []):
            with self.subTest(deny=deny):
                self.assertEqual(score(self.sdk(deny))[1], score(self.native(deny))[1])

    def test_a_rule_without_a_wildcard_matches_only_the_bare_command(self):
        for src in (self.sdk, self.native):
            with self.subTest(source=src.__name__):
                self.assertNotEqual(score(src(["Bash(git push)", "Bash(rm -rf)"]))[1][2], "VERIFIED")
                self.assertEqual(score(src(["Bash(git push *)", "Bash(rm -rf:*)"]))[1][2], "VERIFIED")


class R3_06_SandboxEscapes(unittest.TestCase):
    OTHERS = ["Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "Read", "Grep", "Glob"]
    SECRETS = ["Read(./**/.env*)", "Read(./**/*.pem)", "Read(~/.ssh/**)"]

    def settings(self, sandbox, deny=(), ask=(), allow=("Bash(*)",)):
        data = {"permissions": {"allow": list(allow), "deny": self.OTHERS + list(deny), "ask": list(ask)}}
        if sandbox is not None:
            data["sandbox"] = sandbox
        return {".claude/settings.json": json.dumps(data)}

    def test_codex_fixtures_lose_unsupported_credit(self):
        for name in ("sandbox_excluded", "sandbox_ask"):
            with self.subTest(fixture=name):
                g = guards(audit(FIX / name))
                self.assertNotEqual(g["G2"]["status"], "VERIFIED", g)

    def test_read_denies_bind_bash_only_in_a_sandbox_without_escapes(self):
        deny = self.SECRETS + ["Bash(git push *)", "Bash(rm -rf *)"]
        closed = {"enabled": True, "allowUnsandboxedCommands": False}
        cases = {"closed sandbox": (closed, "VERIFIED"),
                 "sandbox off": (None, "not"),
                 "sandbox disabled": ({"enabled": False, "allowUnsandboxedCommands": False}, "not"),
                 "excluded command (Codex)": (dict(closed, excludedCommands=["python *"]), "not"),
                 "unsandboxed commands allowed (default)": ({"enabled": True}, "not"),
                 "unsandboxed commands allowed (explicit)": ({"enabled": True, "allowUnsandboxedCommands": True}, "not")}
        for name, (sb, want) in cases.items():
            with self.subTest(case=name):
                st = score(self.settings(sb, deny=deny))[1]
                if want == "VERIFIED":
                    self.assertEqual(st[1], "VERIFIED", st)
                else:
                    self.assertNotEqual(st[1], "VERIFIED", st)

    def test_auto_allow_skips_a_whole_bash_ask(self):
        closed = {"enabled": True, "allowUnsandboxedCommands": False}
        self.assertEqual(score(self.settings(dict(closed, autoAllowBashIfSandboxed=False), ask=["Bash(*)"]))[0], 8)
        self.assertEqual(score(self.settings(None, ask=["Bash(*)"]))[0], 8)
        for name, sb in {"auto-allow on": dict(closed, autoAllowBashIfSandboxed=True),
                         "auto-allow on by default": closed}.items():
            for ask in (["Bash(*)"], ["Bash"]):
                with self.subTest(sandbox=name, ask=ask):
                    pts, st, g = score(self.settings(sb, ask=ask))
                    self.assertEqual(pts, 0, g)


class R3_07_ReadsStayInTheRoot(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.repo, self.outside = self.base / "repo", self.base / "constructed_outside"
        self.repo.mkdir()
        self.outside.mkdir()
        shutil.copy(FIX / "constructed_outside" / "settings.json", self.outside / "settings.json")
        self.a = load_audit()

    def tearDown(self):
        shutil.rmtree(self.base)

    def test_a_linked_claude_directory_is_not_read(self):
        (self.repo / ".claude").symlink_to("../constructed_outside", target_is_directory=True)
        r = self.a.Repo(self.repo)
        self.assertEqual(r.text(self.repo / ".claude" / "settings.json"), "")
        rep = audit(self.repo)
        self.assertEqual(points(rep), 0, guards(rep))
        self.assertNotIn("VERIFIED", statuses(rep))

    def test_final_component_and_parent_links_out_are_not_read_in_tree_links_are(self):
        (self.outside / "notes.md").write_text("outside canary\n")
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "real.md").write_text("in-tree text\n")
        (self.repo / "docs" / "same.md").symlink_to("real.md")
        (self.repo / "docs_link").symlink_to("docs", target_is_directory=True)
        (self.repo / "file_out.md").symlink_to(self.outside / "notes.md")
        (self.repo / "dir_out").symlink_to(self.outside, target_is_directory=True)
        r = self.a.Repo(self.repo)
        self.assertEqual(r.text(self.repo / "docs" / "real.md"), "in-tree text\n")
        self.assertEqual(r.text(self.repo / "docs" / "same.md"), "in-tree text\n")
        self.assertEqual(r.text(self.repo / "docs_link" / "real.md"), "in-tree text\n")
        self.assertEqual(r.text(self.repo / "file_out.md"), "")
        self.assertEqual(r.text(self.repo / "dir_out" / "notes.md"), "")
        self.assertEqual(r.text(self.repo / "dir_out" / "settings.json"), "")


class CanonicalFormsAreOneList(unittest.TestCase):
    """The scorer, `--canonical-forms` and the audit's SKILL.md read the same list; the helper the audit trusts by
    hash refuses every probe the coverage rule (F7) uses."""

    def test_the_docs_section_is_the_scorer_list(self):
        a = load_audit()
        out = subprocess.run([sys.executable, str(ROOT / "plugins/harness-audit/skills/audit/scripts/audit.py"),
                              "--canonical-forms"], capture_output=True, text=True)
        self.assertEqual(out.stdout.rstrip("\n"), a.canonical_forms_text())
        skill = (ROOT / "plugins/harness-audit/skills/audit/SKILL.md").read_text()
        block = skill.split("<!-- canonical-forms:start", 1)[1].split("-->", 1)[1].split("<!-- canonical-forms:end -->")[0]
        self.assertEqual(block.strip("\n"), a.canonical_forms_text())
        self.assertEqual([n for n, _ in a.CANONICAL_FORMS], [f"F{i} " + n.split(" ", 1)[1] for i, n in
                                                              enumerate((n for n, _ in a.CANONICAL_FORMS), 1)])

    def test_the_pinned_helper_is_the_shipped_one_and_its_copies(self):
        a = load_audit()
        data = KIT_GUARD.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), a.KIT_GUARD_SHA256)
        self.assertEqual((ROOT / "kit/tracks/claude-agent-sdk/kit_guard.py").read_bytes(), data)

    # 1.4.5: the helper's F7 probe test is replaced by the generated class table in tests/test_kit_guard.py


class JudgementFixtures(unittest.TestCase):
    def test_allowlist_same_condition_and_try_stay_unresolved(self):
        for name in ("allowlist", "same_condition", "try_refusal"):
            with self.subTest(fixture=name):
                rep = audit(FIX / name)
                self.assertEqual(statuses(rep), ("UNRESOLVED",) * 3, guards(rep))


if __name__ == "__main__":
    unittest.main()
