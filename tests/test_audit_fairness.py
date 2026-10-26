"""Fairness matrix for harness-audit's guard checks (G1-G3): the same guard quality earns the same points on
every supported framework, and the same broad capability loses the same points.

Every fixture is a tiny repo written to a temp folder. The audit only reads it: one test patches
subprocess, exec and import machinery while auditing a repo whose code would fail loudly if it ran.
"""
import builtins
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
CLAUDE_SETTINGS = ROOT / "plugins/harness-init/skills/init/templates/.claude/settings.json"
GUARD = ("G1", "G2", "G3")
FULL_GUARD = 8  # G1 3 + G2 3 + G3 2

# ------------------------------------------------------------------ fixtures
NEXT_ITEM = '''
def next_item() -> str:
    """Return the next work item whose passes is false, as JSON."""
    data = json.loads((REPO / "progress/feature_list.json").read_text())
    return json.dumps(next((i for i in data["items"] if not i.get("passes")), {"done": True}))


def run_init() -> str:
    """Run the project's smoke test and return the last 40 lines."""
    p = subprocess.run(["bash", "init.sh"], cwd=REPO, capture_output=True, text=True, timeout=300)
    return "\\n".join((p.stdout + p.stderr).splitlines()[-40:])
'''

BROAD = {  # category -> tool function source (the same body on every framework)
    "shell": '''
def run_shell(command: str) -> str:
    """Run any shell command."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
''',
    "write": '''
def write_file(path: str, content: str) -> str:
    """Write any file."""
    with open(path, "w") as f:
        f.write(content)
    return "ok"
''',
    "fetch": '''
def fetch(url: str) -> str:
    """Fetch any URL."""
    return urllib.request.urlopen(url).read().decode()
''',
    "computer": '''
def click(x: int, y: int) -> str:
    """Click anywhere on the screen."""
    pyautogui.click(x, y)
    return "clicked"
''',
}
BROAD_NAME = {"shell": "run_shell", "write": "write_file", "fetch": "fetch", "computer": "click"}

FRAMEWORKS = {
    # name: (requirements line, imports, decorator, agent construction with {tools})
    "langgraph": ("langgraph==1.2.17\nlangchain==1.4.7\n",
                  "from langchain.agents import create_agent\nfrom langchain_core.tools import tool\n",
                  "@tool\n", "agent = create_agent(model, [{tools}], system_prompt='work one item')\n"),
    "openai-agents-sdk": ("openai-agents==0.24.0\n", "from agents import Agent, function_tool\n",
                          "@function_tool\n", "agent = Agent(name='kit', instructions='work one item', tools=[{tools}])\n"),
    "crewai": ("crewai==1.15.30\n", "from crewai import Agent\nfrom crewai.tools import tool\n",
               "@tool('{name}')\n", "agent = Agent(role='worker', goal='one item', backstory='b', tools=[{tools}])\n"),
    "strands-agents": ("strands-agents==1.62.0\n", "from strands import Agent, tool\n",
                       "@tool\n", "agent = Agent(model=model, tools=[{tools}], system_prompt='work one item')\n"),
    "google-adk": ("google-adk==2.13.0\n", "from google.adk.agents import Agent\n",
                   "", "root_agent = Agent(name='kit', model='m', tools=[{tools}]{extra})\n"),
    "microsoft-agent-framework": ("agent-framework==1.23.0\n", "from agent_framework import Agent, tool\n",
                                  "@tool\n", "agent = Agent(client, 'work one item', tools=[{tools}])\n"),
}

GATES = {  # the framework's own approval / deny mechanism, covering secrets and destructive commands
    "langgraph": '''
from langchain.agents.middleware import HumanInTheLoopMiddleware
SECRET = r"(\\.env|\\.pem|\\.key|\\.ssh|\\.aws)"
DESTRUCTIVE = r"(git push|reset --hard|rm -rf)"
gate = HumanInTheLoopMiddleware(interrupt_on={"run_shell": True, "write_file": True, "fetch": True, "click": True})
''',
    "openai-agents-sdk": '''
SECRET = r"(\\.env|\\.pem|\\.key|\\.ssh|\\.aws)"
DESTRUCTIVE = r"(git push|reset --hard|rm -rf)"
# every broad tool below is declared with needs_approval=True
''',
    "crewai": '''
from crewai.hooks import register_before_tool_call_hook
SECRET = r"(\\.env|\\.pem|\\.key|\\.ssh|\\.aws)"
DESTRUCTIVE = r"(git push|reset --hard|rm -rf)"
def block(ctx):
    if re.search(SECRET, str(ctx.tool_input)) or re.search(DESTRUCTIVE, str(ctx.tool_input)):
        return False
    return None
register_before_tool_call_hook(block)
''',
    "google-adk": '''
SECRET = r"(\\.env|\\.pem|\\.key|\\.ssh|\\.aws)"
DESTRUCTIVE = r"(git push|reset --hard|rm -rf)"
def block(tool, args, tool_context):
    if re.search(SECRET, str(args)) or re.search(DESTRUCTIVE, str(args)):
        return {"error": "blocked by the harness"}
    return None
''',
    "microsoft-agent-framework": '''
SECRET = r"(\\.env|\\.pem|\\.key|\\.ssh|\\.aws)"
DESTRUCTIVE = r"(git push|reset --hard|rm -rf)"
# every broad tool below is declared with approval_mode="always_require"
''',
    "strands-agents": '''
from strands.hooks import BeforeToolCallEvent
SECRET = r"(\\.env|\\.pem|\\.key|\\.ssh|\\.aws)"
DESTRUCTIVE = r"(git push|reset --hard|rm -rf)"
def block(event: BeforeToolCallEvent):
    if re.search(SECRET, str(event.tool_use)) or re.search(DESTRUCTIVE, str(event.tool_use)):
        event.cancel_tool = "blocked by the harness"
''',
}


def _write_code_repo(d: Path, fw: str, broad: str | None = None, gated: bool = False):
    req, imports, deco, build = FRAMEWORKS[fw]
    names = ["next_item", "run_init"] + ([BROAD_NAME[broad]] if broad else [])
    src = ["import json, re, subprocess, urllib.request\nfrom pathlib import Path\nimport pyautogui\n", imports,
           "REPO = Path('.')\nmodel = None\n"]
    if gated:
        src.append(GATES[fw])
    # tool functions with the framework's decorator
    for fn_src in NEXT_ITEM.strip().split("\n\n\n") + ([BROAD[broad].strip()] if broad else []):
        name = fn_src.split("def ", 1)[1].split("(", 1)[0]
        d_ = deco.format(name=name)
        if gated and fw == "openai-agents-sdk" and broad and name == BROAD_NAME[broad]:
            d_ = "@function_tool(needs_approval=True)\n"
        if gated and fw == "microsoft-agent-framework" and broad and name == BROAD_NAME[broad]:
            d_ = '@tool(approval_mode="always_require")\n'
        src.append("\n" + d_ + fn_src + "\n")
    extra = ", before_tool_callback=block" if gated and fw == "google-adk" else ""
    src.append("\n" + build.format(tools=", ".join(names), extra=extra))
    (d / "agent.py").write_text("".join(src))
    (d / "requirements.txt").write_text(req)


def _write_claude_repo(d: Path, broad: str | None = None):
    (d / ".claude").mkdir()
    if broad is None:
        shutil.copy(CLAUDE_SETTINGS, d / ".claude" / "settings.json")
    else:  # Claude Code always has shell, file-write and web tools: "broad" means nothing denies them
        allow = {"shell": ["Bash(*)"], "write": ["Write(*)", "Edit(*)"], "fetch": ["WebFetch"],
                 "computer": ["mcp__computer-use__*"]}[broad]
        (d / ".claude" / "settings.json").write_text(json.dumps(
            {"permissions": {"allow": allow, "defaultMode": "bypassPermissions"}}))


def _audit(d: Path) -> dict:
    p = subprocess.run([sys.executable, str(AUDIT), str(d), "--json"], capture_output=True, text=True)
    return json.loads(p.stdout)


def load_audit(name: str):
    spec = importlib.util.spec_from_file_location(name, AUDIT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod          # dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod


def guard_points(rep: dict) -> float:
    credit = {"VERIFIED": 1.0, "DECLARED": 0.5}
    return sum(c["weight"] * credit.get(c["status"], 0) for c in rep["checks"] if c["id"] in GUARD)


def build(kind: str, fw: str, broad: str | None = None, gated: bool = False) -> Path:
    d = Path(tempfile.mkdtemp())
    if fw == "claude-code":
        _write_claude_repo(d, broad)
    else:
        _write_code_repo(d, fw, broad, gated)
    return d


ALL = ["claude-code", *FRAMEWORKS]


def matrix() -> dict:
    """{framework: {"narrow": pts, "shell": pts, ...}} -- used by the tests and by the report."""
    out = {}
    for fw in ALL:
        row = {}
        for variant in ["narrow", "shell", "write", "fetch", "computer"]:
            d = build("x", fw, None if variant == "narrow" else variant)
            try:
                row[variant] = guard_points(_audit(d))
            finally:
                shutil.rmtree(d)
        if fw != "claude-code":
            d = build("x", fw, "shell", gated=True)
            try:
                row["shell+gate"] = guard_points(_audit(d))
            finally:
                shutil.rmtree(d)
        out[fw] = row
    return out


class FairnessMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = matrix()

    def test_narrow_harnesses_get_the_same_full_guard_score(self):
        for fw in ALL:
            self.assertEqual(self.m[fw]["narrow"], FULL_GUARD, (fw, self.m[fw]))

    def test_each_broad_capability_loses_the_same_points_on_every_code_framework(self):
        for variant in ["shell", "write", "fetch", "computer"]:
            pts = {fw: self.m[fw][variant] for fw in FRAMEWORKS}
            self.assertEqual(len(set(pts.values())), 1, (variant, pts))
            self.assertLess(next(iter(pts.values())), FULL_GUARD, variant)

    def test_the_stated_losses_per_capability(self):
        # G1 (3) is lost by any ungated broad tool; G2 (3) by shell, web fetch, computer use (they reach or send
        # secrets); G3 (2) by shell, file-write, computer use (they can destroy or change things irreversibly).
        expected = {"shell": 0, "write": 3, "fetch": 2, "computer": 0}
        for fw in FRAMEWORKS:
            for variant, pts in expected.items():
                self.assertEqual(self.m[fw][variant], pts, (fw, variant))

    def test_claude_code_without_deny_rules_loses_everything_as_before(self):
        for variant in ["shell", "write", "fetch", "computer"]:
            self.assertEqual(self.m["claude-code"][variant], 0, variant)

    def test_a_broad_tool_behind_the_frameworks_own_gate_earns_full_points(self):
        for fw in FRAMEWORKS:
            self.assertEqual(self.m[fw]["shell+gate"], FULL_GUARD, fw)


class GuardEvidence(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_every_guard_pass_names_file_and_line_and_every_gap_names_the_framework_mechanism(self):
        _write_code_repo(self.d, "crewai", "shell")
        rep = _audit(self.d)
        for c in rep["checks"]:
            if c["id"] in GUARD:
                self.assertEqual(c["status"], "MISSING", c)
                self.assertIn("CrewAI", c["fix"])
                self.assertIn("agent.py:", c["evidence"])         # what was found, with file:line
        shutil.rmtree(self.d); self.d.mkdir()
        _write_code_repo(self.d, "strands-agents")
        rep = _audit(self.d)
        for c in rep["checks"]:
            if c["id"] in GUARD:
                self.assertEqual(c["status"], "VERIFIED", c)
                self.assertRegex(c["evidence"], r"agent\.py:\d+")

    def test_framework_native_broad_tools_count_like_hand_written_ones(self):
        cases = {
            "langgraph": "from langchain.agents import create_agent\nfrom langchain_community.tools import ShellTool\n"
                         "agent = create_agent(m, [ShellTool()])\n",
            "openai-agents-sdk": "from agents import Agent, LocalShellTool\nagent = Agent(name='a', tools=[LocalShellTool(executor=x)])\n",
            "crewai": "from crewai import Agent\nagent = Agent(role='r', goal='g', backstory='b', tools=[], allow_code_execution=True)\n",
            "strands-agents": "from strands import Agent\nfrom strands_tools import shell\nagent = Agent(tools=[shell])\n",
        }
        for fw, src in cases.items():
            with self.subTest(fw=fw):
                d = Path(tempfile.mkdtemp())
                try:
                    (d / "agent.py").write_text(src)
                    rep = _audit(d)
                    self.assertEqual(rep["tracks"], [fw])
                    self.assertEqual(guard_points(rep), 0, [c for c in rep["checks"] if c["id"] in GUARD])
                finally:
                    shutil.rmtree(d)

    def test_claude_agent_sdk_allowed_tools_with_its_deny_hook(self):
        (self.d / "agent.py").write_text(
            "import re\nfrom claude_agent_sdk import ClaudeAgentOptions\n"
            "SECRET = re.compile(r'(\\.env|\\.pem|\\.ssh)')\n"
            "def deny(input_data, tool_use_id, context):\n"
            "    return {'hookSpecificOutput': {'permissionDecision': 'deny'}}\n"
            "opts = ClaudeAgentOptions(allowed_tools=['Read', 'Bash'], disallowed_tools=['Bash(rm -rf *)'])\n")
        self.assertEqual(guard_points(_audit(self.d)), FULL_GUARD)
        (self.d / "agent.py").write_text("from claude_agent_sdk import ClaudeAgentOptions\n"
                                          "opts = ClaudeAgentOptions(allowed_tools=['Read', 'Bash'])\n")
        self.assertEqual(guard_points(_audit(self.d)), 0)

    def test_the_track_detected_is_reported(self):
        _write_code_repo(self.d, "openai-agents-sdk")
        rep = _audit(self.d)
        self.assertEqual(rep.get("tracks"), ["openai-agents-sdk"])

    def test_test_files_are_not_mistaken_for_the_agent(self):
        (self.d / "tests").mkdir()
        (self.d / "tests" / "test_x.py").write_text("from langgraph import x\nagent = create_agent(m, [shell])\n")
        rep = _audit(self.d)
        self.assertEqual(rep.get("tracks"), [])

    def test_assess_only_track_scores_declared_at_half_weight(self):
        (self.d / "requirements.txt").write_text("pydantic-ai==2.61.0\n")
        (self.d / "agent.py").write_text("from pydantic_ai import Agent\nagent = Agent('m', tools=[])\n")
        rep = _audit(self.d)
        self.assertEqual(rep.get("tracks"), ["pydantic-ai"])
        self.assertEqual(guard_points(rep), 0)  # nothing declared yet
        (self.d / "docs").mkdir()
        (self.d / "docs" / "IMPACT.md").write_text(
            "# Impact\n\n## Tools\n- next_item, run_init only\n\n## Secrets\n- no file or shell tool\n\n"
            "## Destructive actions\n- none; writes go through a person\n")
        rep = _audit(self.d)
        statuses = {c["id"]: c["status"] for c in rep["checks"] if c["id"] in GUARD}
        self.assertEqual(statuses, {"G1": "DECLARED", "G2": "DECLARED", "G3": "DECLARED"})
        self.assertEqual(guard_points(rep), FULL_GUARD / 2)
        self.assertIn("declared", next(c for c in rep["checks"] if c["id"] == "G1")["evidence"].lower())

    def test_declared_never_overrides_derived_evidence(self):
        _write_code_repo(self.d, "langgraph", "shell")
        (self.d / "docs").mkdir()
        (self.d / "docs" / "IMPACT.md").write_text("## Tools\n- all fine\n## Secrets\n- fine\n## Destructive\n- fine\n")
        self.assertEqual(guard_points(_audit(self.d)), 0)

    def test_the_audit_never_executes_or_imports_the_audited_repo(self):
        _write_code_repo(self.d, "langgraph", "shell")
        (self.d / "agent.py").write_text((self.d / "agent.py").read_text() + "\nraise SystemExit('EXECUTED')\n")
        (self.d / "sitecustomize.py").write_text("raise SystemExit('IMPORTED')\n")
        mod = load_audit("audit_under_test")
        real_import = builtins.__import__

        def no_repo_import(name, *a, **k):
            if name in {"agent", "sitecustomize"}:
                raise AssertionError(f"audit imported {name}")
            return real_import(name, *a, **k)

        def boom(*a, **k):
            raise AssertionError("audit tried to run something")

        with mock.patch.object(subprocess, "run", boom), mock.patch.object(subprocess, "Popen", boom), \
                mock.patch.object(builtins, "exec", boom), mock.patch.object(builtins, "__import__", no_repo_import), \
                mock.patch("os.system", boom):
            rep = mod.audit(self.d)
        self.assertIn("langgraph", rep.tracks)

    def test_existing_claude_scoring_is_unchanged(self):
        _write_claude_repo(self.d)
        rep = _audit(self.d)
        self.assertEqual(guard_points(rep), FULL_GUARD)
        self.assertEqual(rep.get("tracks"), [])
        g1 = next(c for c in rep["checks"] if c["id"] == "G1")
        self.assertIn(".claude/settings.json:", g1["evidence"])


class EmbeddedSignatures(unittest.TestCase):
    def test_audit_detect_table_matches_the_track_spec_files(self):
        mod = load_audit("audit_sig")
        want = {}
        for p in sorted((ROOT / "kit/tracks").glob("*/harness_track.json")):
            d = json.loads(p.read_text())
            if d["id"] == "claude-code":
                continue
            want[d["id"]] = (d["support"], [(s["file"], s["contains"]) for s in d["detect"]])
        have = {k: (v["support"], [tuple(x) for x in v["detect"]]) for k, v in mod.TRACK_SIGNATURES.items()}
        self.assertEqual(have, want)


if __name__ == "__main__":
    unittest.main()
