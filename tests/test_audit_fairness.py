"""Fairness tests for harness-audit's guard checks (G1-G3), written around the invariant rather than around which
mechanism names appear:

  * the same guard behaviour earns the same points on every track, and the same unguarded capability loses the
    same points;
  * a guard earns credit only where it is attached to the agent and tool being scored and covers that capability;
  * what the audit cannot resolve statically is UNRESOLVED, never VERIFIED;
  * the audit never imports or runs the repo it audits.

Points: G1 3 (every broad tool gated), G2 3 (every tool that can reach or send secrets refuses them or needs a
person), G3 2 (every tool that can destroy or change things irreversibly refuses that or needs a person).
Fixtures under tests/fixtures/codex_r1 come from Codex's round-1 review of 1.4.1 (see its README).
"""
import builtins
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "plugins/harness-audit/skills/audit/scripts/audit.py"
FIX = ROOT / "tests/fixtures/codex_r1"
CLAUDE_TEMPLATE = ROOT / "plugins/harness-init/skills/init/templates/.claude/settings.json"
GUARD = ("G1", "G2", "G3")
TRACKS = ["claude-code", "claude-agent-sdk", "microsoft-agent-framework", "google-adk", "langgraph",
          "openai-agents-sdk", "crewai", "strands-agents"]
EXPECTED = {"a": 8, "b": 0, "c": 2}   # c: shell guarded, web fetch not -> lose G1 and G2, keep G3
# plugins/harness-audit/skills/audit/scripts/audit.py at 24bc1da (1.4.1), for the base comparison
BASE_AUDIT = ROOT / "tests/fixtures/audit_1_4_1/audit.py.txt"
BASE_AUDIT_BLOB = "c030f56a9fcc36c0a94bbfe67850ef844f1a343d"
BASE_AUDIT_SHA256 = "79c2421797164777a726107e68e243d7bd57a57f5cee6ce2d17b3aefc8d9b171"


def load_audit(name="audit_under_test"):
    spec = importlib.util.spec_from_file_location(name, AUDIT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def audit(path: Path) -> dict:
    p = subprocess.run([sys.executable, str(AUDIT), str(path), "--json"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def points(rep: dict) -> float:
    credit = {"VERIFIED": 1.0, "DECLARED": 0.5}
    return sum(c["weight"] * credit.get(c["status"], 0) for c in rep["checks"] if c["id"] in GUARD)


def guards(rep: dict) -> dict:
    return {c["id"]: c for c in rep["checks"] if c["id"] in GUARD}


class Repo:
    """A throwaway repo written from strings."""

    def __init__(self, files: dict):
        self.d = Path(tempfile.mkdtemp())
        for rel, text in files.items():
            p = self.d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)

    def __enter__(self):
        return self.d

    def __exit__(self, *a):
        shutil.rmtree(self.d)


SECRET = 'SECRET = re.compile(r"(\\.env|\\.pem|\\.key|\\.ssh|\\.aws)")\n'
REFUSE = ('    if SECRET.search(command) or any(x in command for x in ("git push", "reset --hard", "rm -rf")):\n'
          '        return "denied"\n')
SHELL = ('def run_shell(command: str) -> str:\n    """Execute a shell command."""\n{guard}'
         '    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout\n')


class Matrix(unittest.TestCase):
    """The full 8-track x a/b/c matrix from Codex's probe fixtures."""

    def test_every_track_scores_the_same_for_the_same_guard_behaviour(self):
        got = {}
        for track in TRACKS:
            for v in "abc":
                got[(track, v)] = points(audit(FIX / track / v))
        wrong = {k: p for k, p in got.items() if p != EXPECTED[k[1]]}
        self.assertEqual(wrong, {}, f"expected a=8, b=0, c=2 on every track; got {got}")

    def test_partly_guarded_loses_exactly_g1_and_g2(self):
        for track in TRACKS:
            g = guards(audit(FIX / track / "c"))
            with self.subTest(track=track):
                self.assertEqual((g["G1"]["status"], g["G2"]["status"], g["G3"]["status"]), ("MISSING", "MISSING", "VERIFIED"))
                self.assertRegex(g["G1"]["evidence"], r"fetch|WebFetch")      # names the ungated capability

    def test_every_result_has_file_and_line_or_a_fix(self):
        for track in TRACKS:
            for v in "abc":
                for c in guards(audit(FIX / track / v)).values():
                    if c["status"] == "VERIFIED":
                        self.assertRegex(c["evidence"], r":\d+", (track, v, c))
                    else:
                        self.assertTrue(c["fix"], (track, v, c))


class Attachment(unittest.TestCase):
    """R1-01: a guard counts only where it is attached and covers the capability."""

    def test_two_agents_do_not_share_one_guard(self):
        rep = audit(FIX / "two_agents_one_guard")
        self.assertEqual(points(rep), 0, guards(rep))
        self.assertIn("unguarded", guards(rep)["G1"]["evidence"])

    def test_a_guard_that_is_never_attached_earns_nothing(self):
        rep = audit(FIX / "unattached_guard")
        self.assertEqual(points(rep), 0, guards(rep))

    def test_tool_specific_approval_does_not_cover_a_sibling_tool(self):
        src = ("import re, subprocess\nfrom agents import Agent, function_tool\n" + SECRET +
               "@function_tool(needs_approval=True)\n" + SHELL.format(guard=REFUSE) +
               "@function_tool\ndef other(command: str) -> str:\n    return subprocess.run(command, shell=True).stdout\n"
               "agent = Agent(name='w', tools=[run_shell, other])\n")
        with Repo({"agent.py": src}) as d:
            self.assertEqual(points(audit(d)), 0)

    def test_guard_like_comments_and_unused_constants_earn_nothing(self):
        src = ("import subprocess\nfrom agents import Agent, function_tool\n"
               "# needs_approval=True  interrupt(  cancel_tool =  rm -rf  git push  .env .pem\n"
               "DENY = ['git push', 'rm -rf', '.env', '.pem']\n"
               "@function_tool\ndef run_shell(command: str) -> str:\n    return subprocess.run(command, shell=True).stdout\n"
               "agent = Agent(name='w', tools=[run_shell])\n")
        with Repo({"agent.py": src}) as d:
            self.assertEqual(points(audit(d)), 0)

    def test_langgraph_middleware_counts_only_when_passed_to_the_agent(self):
        base = ("import re, subprocess\nfrom langchain.agents import create_agent\n"
                "from langchain.agents.middleware import HumanInTheLoopMiddleware\n" + SECRET +
                "gate = HumanInTheLoopMiddleware(interrupt_on={'run_shell': True})\n"
                "def run_shell(command: str) -> str:\n    return subprocess.run(command, shell=True).stdout\n")
        with Repo({"agent.py": base + "agent = create_agent(model, [run_shell])\n"}) as d:
            self.assertEqual(points(audit(d)), 0)
        with Repo({"agent.py": base + "agent = create_agent(model, [run_shell], middleware=[gate])\n"}) as d:
            self.assertEqual(points(audit(d)), 8)   # a person approves every shell call: G1, G2 and G3 covered

    def test_strands_hook_counts_only_when_registered(self):
        base = ("import re, subprocess\nfrom strands import Agent, tool\nfrom strands.hooks import HookProvider, BeforeToolCallEvent\n"
                + SECRET + "class Gate(HookProvider):\n    def register_hooks(self, registry, **kw):\n"
                "        registry.add_callback(BeforeToolCallEvent, self.before)\n    def before(self, event):\n"
                "        if SECRET.search(str(event.tool_use)) or 'rm -rf' in str(event.tool_use) or 'git push' in str(event.tool_use):\n"
                "            event.cancel_tool = 'denied'\n"
                "@tool\ndef run_shell(command: str) -> str:\n    return subprocess.run(command, shell=True).stdout\n")
        with Repo({"agent.py": base + "agent = Agent(tools=[run_shell])\n"}) as d:
            self.assertEqual(points(audit(d)), 0)
        with Repo({"agent.py": base + "agent = Agent(tools=[run_shell], hooks=[Gate()])\n"}) as d:
            self.assertEqual(points(audit(d)), 8)

    def test_sdk_deny_function_counts_only_when_attached(self):
        base = ("import re\nfrom claude_agent_sdk import ClaudeAgentOptions, HookMatcher\n" + SECRET +
                "async def deny(data, tool_use_id, context):\n    command = data.get('tool_input', {}).get('command', '')\n"
                "    if SECRET.search(command) or any(x in command for x in ('git push', 'reset --hard', 'rm -rf')):\n"
                "        return {'hookSpecificOutput': {'permissionDecision': 'deny'}}\n    return {}\n")
        with Repo({"agent.py": base + "opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'])\n"}) as d:
            self.assertEqual(points(audit(d)), 0)
        with Repo({"agent.py": base + "opts = ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], "
                                      "hooks={'PreToolUse': [HookMatcher(matcher='Bash', hooks=[deny])]})\n"}) as d:
            self.assertEqual(points(audit(d)), 8)

    def test_unresolved_attachment_is_unresolved_never_verified(self):
        src = ("import subprocess\nfrom agents import Agent, function_tool\nfrom guards import make_guardrail\n"
               "@function_tool(tool_input_guardrails=[make_guardrail()])\n"
               "def run_shell(command: str) -> str:\n    return subprocess.run(command, shell=True).stdout\n"
               "agent = Agent(name='w', tools=[run_shell])\n")
        with Repo({"agent.py": src}) as d:
            g = guards(audit(d))
            self.assertNotIn("VERIFIED", {c["status"] for c in g.values()})
            self.assertIn("UNRESOLVED", {c["status"] for c in g.values()})


class Resolution(unittest.TestCase):
    """R1-02: tools are followed through imports, aliases and helpers; what can't be followed is UNRESOLVED."""

    def test_imported_broad_tool_loses_credit(self):
        rep = audit(FIX / "imported_broad_tool")
        self.assertEqual(points(rep), 0, guards(rep))
        self.assertIn("tool_impl.py", guards(rep)["G1"]["evidence"])

    def test_aliased_subprocess_loses_credit(self):
        self.assertEqual(points(audit(FIX / "aliased_subprocess")), 0)

    def test_local_imported_aliased_and_helper_wrapped_tools_score_alike(self):
        variants = {
            "local": {"agent.py": "import subprocess\nfrom agents import Agent\n"
                                  "def run(command):\n    return subprocess.run(command, shell=True).stdout\n"
                                  "agent = Agent(name='w', tools=[run])\n"},
            "imported": {"agent.py": "from agents import Agent\nfrom pkg.impl import run\nagent = Agent(name='w', tools=[run])\n",
                         "pkg/__init__.py": "", "pkg/impl.py": "import subprocess\ndef run(command):\n    return subprocess.run(command, shell=True).stdout\n"},
            "alias": {"agent.py": "from agents import Agent\nfrom subprocess import run as go\n"
                                  "def run(command):\n    return go(command, shell=True).stdout\nagent = Agent(name='w', tools=[run])\n"},
            "module_alias": {"agent.py": "from agents import Agent\nimport impl as tools_mod\nagent = Agent(name='w', tools=[tools_mod.run])\n",
                             "impl.py": "import os\ndef run(command):\n    return os.system(command)\n"},
            "helper": {"agent.py": "import subprocess\nfrom agents import Agent\n"
                                   "def _exec(cmd):\n    return subprocess.run(cmd, shell=True).stdout\n"
                                   "def run(command):\n    return _exec(command)\nagent = Agent(name='w', tools=[run])\n"},
        }
        for name, files in variants.items():
            with self.subTest(variant=name), Repo(files) as d:
                rep = audit(d)
                self.assertEqual(points(rep), 0, (name, guards(rep)))
                self.assertIn("shell", guards(rep)["G1"]["evidence"])

    def test_a_tool_the_audit_cannot_follow_is_unresolved(self):
        src = "from agents import Agent\nfrom some_vendor_pkg import mystery_tool\nagent = Agent(name='w', tools=[mystery_tool])\n"
        with Repo({"agent.py": src}) as d:
            g = guards(audit(d))
            self.assertEqual({c["status"] for c in g.values()}, {"UNRESOLVED"})
            self.assertIn("mystery_tool", g["G1"]["evidence"])

    def test_a_narrow_imported_tool_still_earns_full_credit(self):
        files = {"agent.py": "from agents import Agent\nfrom impl import next_item\nagent = Agent(name='w', tools=[next_item])\n",
                 "impl.py": "import json\ndef next_item():\n    return json.dumps({'id': 'F-001'})\n"}
        with Repo(files) as d:
            self.assertEqual(points(audit(d)), 8)


class Refusals(unittest.TestCase):
    """R1-03: equal refusal behaviour, equal credit; unclear analysis is UNRESOLVED, not MISSING."""

    def test_inline_wrapper_refusal_earns_g2_and_g3_like_a_native_hook(self):
        inline = audit(FIX / "inline_real_guard")
        native = ("import re, subprocess\nfrom crewai import Agent\nfrom crewai.tools import tool\n"
                  "from crewai.hooks import register_before_tool_call_hook\n" + SECRET +
                  "def gate(ctx):\n    command = str(ctx.tool_input)\n"
                  "    if SECRET.search(command) or any(x in command for x in ('git push', 'reset --hard', 'rm -rf')):\n"
                  "        return False\n    return None\nregister_before_tool_call_hook(gate)\n"
                  "@tool('run_shell')\n" + SHELL.format(guard="") + "agent = Agent(role='r', goal='g', backstory='b', tools=[run_shell])\n")
        with Repo({"agent.py": native}) as d:
            self.assertEqual(points(inline), points(audit(d)))
        self.assertEqual(points(inline), 8, guards(inline))

    def test_removing_the_early_return_loses_the_credit(self):
        src = (FIX / "inline_real_guard" / "agent.py").read_text().replace('        return "denied"\n', '        pass\n')
        with Repo({"agent.py": src}) as d:
            self.assertEqual(points(audit(d)), 0)

    def test_a_refusal_the_audit_cannot_read_is_unresolved_not_missing(self):
        src = ("import subprocess\nfrom agents import Agent, function_tool\nfrom policy import is_allowed\n"
               "@function_tool\ndef run_shell(command: str) -> str:\n    if not is_allowed(command):\n        return 'denied'\n"
               "    return subprocess.run(command, shell=True).stdout\nagent = Agent(name='w', tools=[run_shell])\n")
        with Repo({"agent.py": src}) as d:
            g = guards(audit(d))
            self.assertEqual(g["G2"]["status"], "UNRESOLVED", g)
            self.assertEqual(g["G3"]["status"], "UNRESOLVED", g)


class ClaudeCode(unittest.TestCase):
    """R1-04: Claude Code deny rules must actually apply."""

    def settings(self, perms):
        return Repo({".claude/settings.json": json.dumps({"permissions": perms})})

    def test_missing_empty_or_irrelevant_deny_lists_earn_no_g1(self):
        for perms in ({"allow": ["Bash(*)"]}, {"deny": [], "allow": ["Bash(*)"]},
                      {"deny": ["Read(./docs/old.txt)"], "allow": ["Bash(*)", "WebFetch"]}):
            with self.subTest(perms=perms), self.settings(perms) as d:
                self.assertEqual(guards(audit(d))["G1"]["status"], "MISSING")

    def test_meaningful_applicable_restrictions_still_earn_credit(self):
        with Repo({".claude/settings.json": CLAUDE_TEMPLATE.read_text()}) as d:
            self.assertEqual(points(audit(d)), 8)

    def test_base_comparison_shows_the_correction_is_intentional(self):
        """1.4.1 and earlier gave 3 points for the word "deny" (Codex's fixture b); 1.4.2 gives 0. Template unchanged."""
        # 1.4.1's audit.py is vendored (no git history needed: CI checks out shallow, downloads have no .git) and
        # pinned by its git blob id and sha256. A mismatch fails the test; it never skips.
        data = BASE_AUDIT.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), BASE_AUDIT_SHA256, "vendored 1.4.1 audit.py changed")
        self.assertEqual(hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest(), BASE_AUDIT_BLOB)
        base = Path(tempfile.mkdtemp()) / "audit_1_4_1.py"
        base.write_bytes(data)
        old = lambda p: json.loads(subprocess.run([sys.executable, str(base), str(p), "--json"], capture_output=True, text=True).stdout)
        self.assertEqual(points(old(FIX / "claude-code" / "b")), 3)
        self.assertEqual(points(audit(FIX / "claude-code" / "b")), 0)
        with Repo({".claude/settings.json": CLAUDE_TEMPLATE.read_text()}) as d:
            self.assertEqual(points(old(d)), points(audit(d)))
        shutil.rmtree(base.parent)


class Aggregation(unittest.TestCase):
    def test_a_guarded_surface_does_not_hide_an_unguarded_one(self):
        self.assertEqual(points(audit(FIX / "mixed")), 0)

    def test_declarations_never_override_derived_failure(self):
        self.assertEqual(points(audit(FIX / "full_plus_declared")), 0)

    def test_assess_only_declared_harness_scores_half(self):
        for d in sorted((FIX / "assess").iterdir()):
            rep = audit(d)
            with self.subTest(track=d.name):
                self.assertEqual(rep["tracks"], [d.name])
                self.assertEqual({c["status"] for c in guards(rep).values()}, {"DECLARED"})
                self.assertEqual(points(rep), 4)

    def test_kit_starters_score_full_guard_points(self):
        for t in ["claude-agent-sdk", "google-adk", "microsoft-agent-framework", "langgraph", "openai-agents-sdk", "crewai", "strands-agents"]:
            with self.subTest(track=t):
                rep = audit(ROOT / "kit" / "tracks" / t)
                self.assertEqual(points(rep), 8, guards(rep))

    def test_test_files_are_not_mistaken_for_the_agent(self):
        with Repo({"tests/test_x.py": "from langgraph import x\nagent = create_agent(m, [shell])\n"}) as d:
            self.assertEqual(audit(d)["tracks"], [])


class StaticOnly(unittest.TestCase):
    def test_the_audit_never_executes_or_imports_the_audited_repo(self):
        files = {"agent.py": (FIX / "imported_broad_tool" / "agent.py").read_text() + "\nraise SystemExit('EXECUTED')\n",
                 "tool_impl.py": (FIX / "imported_broad_tool" / "tool_impl.py").read_text() + "\nraise SystemExit('IMPORTED')\n",
                 "sitecustomize.py": "raise SystemExit('IMPORTED')\n"}
        mod = load_audit()
        real_import = builtins.__import__

        def no_repo_import(name, *a, **k):
            if name.split(".")[0] in {"agent", "tool_impl", "sitecustomize"}:
                raise AssertionError(f"audit imported {name}")
            return real_import(name, *a, **k)

        def boom(*a, **k):
            raise AssertionError("audit tried to run something")

        with Repo(files) as d, mock.patch.object(subprocess, "run", boom), mock.patch.object(subprocess, "Popen", boom), \
                mock.patch.object(builtins, "exec", boom), mock.patch.object(builtins, "__import__", no_repo_import), \
                mock.patch("os.system", boom):
            rep = mod.audit(d)
        self.assertIn("openai-agents-sdk", rep.tracks)

    def test_embedded_signatures_match_the_track_spec_files(self):
        mod = load_audit("audit_sig")
        want = {}
        for p in sorted((ROOT / "kit/tracks").glob("*/harness_track.json")):
            d = json.loads(p.read_text())
            if d["id"] != "claude-code":
                want[d["id"]] = (d["support"], [(s["file"], s["contains"]) for s in d["detect"]])
        have = {k: (v["support"], [tuple(x) for x in v["detect"]]) for k, v in mod.TRACK_SIGNATURES.items()}
        self.assertEqual(have, want)


if __name__ == "__main__":
    unittest.main()
