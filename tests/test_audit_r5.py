"""Codex round-5 findings on 1.4.5b (R5-01 to R5-04), written as the invariant the audit must hold from 1.4.6 on.

R5-01  a glob in a path-like word is over-approximated: a bracket expression is one any-character, `?` one character,
       `*` anything. The helper refuses the word when that superset can match a documented secret name.
R5-02  F2 normalises positional and keyword arguments against the capability's real signature. Only the tested
       parameter carries the operation; every other supplied argument is on a short written allow-list, or no credit.
R5-03  the helper imports nothing a repository file can shadow, and the audit refuses credit when a repo file beside a
       guard module (or at the root) shadows a standard-library module.
R5-04  guard credit on a Claude Agent SDK agent holds only when every other hook provably returns `{}`, None or the
       literal deny: no `updatedInput`, no named value, computed key, helper return or import. Hooks may run in
       parallel, so the registration order never matters.

Fixtures under tests/fixtures/codex_r5 come from Codex's round-5 review of 1.4.5b (see its README). The shipped helper
is written into each throwaway copy, so these tests always run against the helper of the tree under test.
"""
import ast
import asyncio
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

from test_audit_fairness import GUARD, HELPER, ROOT, Repo, audit, guards, points
from test_audit_nearmiss import KINDS, TOOL_HEAD, TOOL_WIRE, score

FIX = ROOT / "tests/fixtures/codex_r5"
KIT_GUARD = ROOT / "kit/shared/kit_guard.py"
SENTINEL = "CONSTRUCTED_SECRET_SENTINEL"


def load_kit_guard(path=KIT_GUARD, name="kit_guard_r5"):
    spec = importlib.util.spec_from_file_location(name, path)
    kg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kg)
    return kg


class FixtureCopy:
    """A throwaway copy of one round-5 fixture with the shipped helper beside it (and any extra files)."""

    def __init__(self, name, extra=None, replace=None):
        self.d = Path(tempfile.mkdtemp())
        shutil.copytree(FIX / name, self.d, dirs_exist_ok=True)
        (self.d / "kit_guard.py").write_text(HELPER)
        for rel, text in (extra or {}).items():
            p = self.d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        for old, new in (replace or {}).items():
            a = self.d / "agent.py"
            a.write_text(a.read_text().replace(old, new))

    def __enter__(self):
        return self.d

    def __exit__(self, *a):
        shutil.rmtree(self.d)


def fixture_points(name, **kw):
    with FixtureCopy(name, **kw) as d:
        rep = audit(d)
        return points(rep), {c: g["status"] for c, g in guards(rep).items()}


class R5Acceptance(unittest.TestCase):
    """Codex's acceptance tests (test_r5_acceptance.py), made strict: a fixture that does not hold loses all credit."""

    def no_credit(self, name):
        pts, st = fixture_points(name)
        self.assertEqual(pts, 0, st)
        self.assertNotIn("VERIFIED", st.values())

    def test_glob_covering_id_dsa_is_refused(self):
        kg = load_kit_guard()
        for v in ("cat id_d*", "cat id_ec*", "cat *dsa"):
            with self.subTest(value=v):
                self.assertTrue(kg.refuses(v))

    def test_positional_executable_cannot_earn_class_credit(self):
        self.no_credit("positional_executable")

    def test_positional_env_cannot_earn_class_credit(self):
        self.no_credit("positional_env")

    def test_shadowed_helper_dependency_cannot_earn_class_credit(self):
        self.no_credit("shadow_shlex")

    def test_dynamic_hook_output_cannot_earn_class_credit(self):
        self.no_credit("sdk_dynamic_output")

    def test_paired_controls(self):
        self.assertEqual(fixture_points("plain")[0], 8)
        self.no_credit("keyword_executable_control")
        self.no_credit("sdk_literal_output_control")


class R5Runtime(unittest.TestCase):
    """What actually runs, on constructed files in a throwaway folder (no network, no installs)."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)

    def test_the_glob_reaches_a_constructed_secret_and_the_helper_refuses_it(self):
        (self.d / "id_dsa").write_text(SENTINEL + "\n")
        (self.d / "id_ecdsa").write_text(SENTINEL + "\n")
        kg = load_kit_guard()
        for word, name in (("id_d*", "id_dsa"), ("id_ec*", "id_ecdsa"), ("*dsa", "id_dsa"), ("id_[d]sa", "id_dsa"),
                           ("id_?sa", "id_dsa")):
            with self.subTest(glob=word):
                out = subprocess.run(["/bin/sh", "-c", f"printf '%s\\n' {word}"], cwd=self.d, capture_output=True,
                                     text=True).stdout.split()
                self.assertIn(name, out)                 # the shell really expands the word to the secret
                self.assertTrue(kg.refuses(f"cat {word}"))

    def test_a_positional_executable_chooses_what_runs(self):
        (self.d / "id_dsa").write_text(SENTINEL + "\n")
        runner = self.d / "constructed_runner"
        runner.write_text(f"#!/bin/sh\ncat '{self.d / 'id_dsa'}' > '{self.d / 'disclosed.txt'}'\n")
        runner.chmod(0o755)
        kg = load_kit_guard()
        self.assertFalse(kg.refuses("ordinary"))
        rc = subprocess.Popen("ordinary", -1, str(runner)).wait()      # the third positional parameter is executable
        self.assertEqual(rc, 0)
        self.assertEqual((self.d / "disclosed.txt").read_text().strip(), SENTINEL)
        pts, st = fixture_points("positional_executable",
                                 replace={"/constructed/positional_executable/constructed_runner": str(runner)})
        self.assertEqual(pts, 0, st)

    def test_the_helper_imports_nothing(self):
        tree = ast.parse(KIT_GUARD.read_text())
        imports = [ast.dump(n) for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertEqual(imports, [])
        calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertNotIn("__import__", calls)

    def test_the_helper_behaves_the_same_with_a_shadow_module_beside_it(self):
        """A fresh interpreter started in a folder whose modules shadow the standard library (and the old helper's
        imports) gets the same answers as this process."""
        values = ["git push", "rm -rf constructed_disposable", "cat id_d*", "cat .env", "cat %2eenv", "cat .{env,x}",
                  "ls -la", "cat README.md", "bash -c 'git push'", "x=1\ncat ~/.ssh/id_rsa", "echo ok"]
        broken = "raise ImportError('constructed shadow')\n"
        shadows = {"shlex.py": "class shlex:\n    def __init__(self, *a, **k): pass\n    def __iter__(self): return iter([])\n",
                   "re.py": broken, "fnmatch.py": "def fnmatchcase(name, pat):\n    return False\n",
                   "urllib/__init__.py": "", "urllib/parse.py": "def unquote(s):\n    return ''\n",
                   "__future__.py": broken, "copy.py": broken, "string.py": broken, "functools.py": broken,
                   "enum.py": broken, "typing.py": broken, "collections/__init__.py": broken, "codecs.py": broken}
        for rel, text in shadows.items():
            p = self.d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        (self.d / "kit_guard.py").write_text(HELPER)
        script = ("import json, sys\nsys.path.insert(0, '')\nimport kit_guard\n"
                  f"print(json.dumps([kit_guard.refuses(v) for v in {values!r}]))\n")
        # json is imported before the folder goes on the path, so only the helper's own imports can be shadowed
        p = subprocess.run([sys.executable, "-I", "-c", script], cwd=self.d, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        kg = load_kit_guard()
        self.assertEqual(p.stdout.strip(), str([kg.refuses(v) for v in values]).replace("T", "t").replace("F", "f"))
        self.assertTrue(kg.refuses("git push") and kg.refuses("rm -rf constructed_disposable"))

    def test_a_second_sdk_hook_output_replaces_the_input_the_guard_passed(self):
        """Python-level: the guard returns {} for an ordinary command and the second hook's output carries an
        updatedInput the helper would refuse (no SDK engine is run here)."""
        fake = types.ModuleType("claude_agent_sdk")
        fake.ClaudeAgentOptions = lambda **k: k
        fake.HookMatcher = lambda **k: k
        sys.modules["claude_agent_sdk"] = fake
        self.addCleanup(sys.modules.pop, "claude_agent_sdk", None)
        sys.modules["kit_guard"] = load_kit_guard()
        self.addCleanup(sys.modules.pop, "kit_guard", None)
        ns = {}
        exec(compile((FIX / "sdk_dynamic_output/agent.py").read_text(), "agent.py", "exec"), ns)
        data = {"tool_name": "Bash", "tool_input": {"command": "echo ordinary"}}
        self.assertEqual(asyncio.run(ns["gate"](data, "t", None)), {})
        out = asyncio.run(ns["rewrite"](data, "t", None))
        replaced = out["hookSpecificOutput"]["updatedInput"]
        self.assertTrue(sys.modules["kit_guard"].refuses(replaced))
        pts, st = fixture_points("sdk_dynamic_output")
        self.assertEqual(pts, 0, st)


# ------------------------------------------------------------------ generated near-misses (round 5)
def tool(body, header="def run(command):\n"):
    return {"agent.py": TOOL_HEAD + "import io, codecs, urllib.request, httpx, asyncio\nfrom kit_guard import refuses\n" +
            header + "    if refuses(command):\n        return 'denied'\n" + body + TOOL_WIRE}


# Capability signatures (positional parameters after the operation argument), as in the standard library.
POPEN_REST = ["bufsize", "executable", "stdin", "stdout", "stderr", "preexec_fn", "close_fds", "shell", "cwd", "env",
              "universal_newlines", "startupinfo", "creationflags", "restore_signals", "start_new_session", "pass_fds"]
SIGNATURES = {
    "subprocess.run": POPEN_REST, "subprocess.call": POPEN_REST, "subprocess.check_call": POPEN_REST,
    "subprocess.check_output": POPEN_REST, "subprocess.Popen": POPEN_REST,
    "os.popen": ["mode", "buffering"], "asyncio.create_subprocess_shell": ["stdin", "stdout", "stderr", "limit"],
    "open": ["mode", "buffering", "encoding", "errors", "newline", "closefd", "opener"],
    "io.open": ["mode", "buffering", "encoding", "errors", "newline", "closefd", "opener"],
    "codecs.open": ["mode", "encoding", "errors", "buffering"],
    "requests.get": ["params"], "requests.post": ["data", "json"], "urllib.request.urlopen": ["data", "timeout"],
}
# Literal values that are on the written allow-list for each parameter (everything else voids the credit).
ALLOWED = {"shell": "True", "cwd": "'src'", "mode": "'r'", "buffering": "-1", "encoding": "'utf-8'", "errors": "'strict'",
           "newline": "None", "universal_newlines": "True", "timeout": "5"}
NOT_ALLOWED_KEYWORDS = {
    "shell": ["executable='/bin/sh'", "env={'BASH_ENV': 'x.sh'}", "preexec_fn=print", "stdin=None", "stdout=None",
              "bufsize=-1", "close_fds=False", "pass_fds=(3,)", "startupinfo=None", "user='root'", "group='wheel'",
              "umask=0", "process_group=0", "start_new_session=True", "input='x'", "cwd='/'", "cwd='../x'", "cwd='~'",
              "cwd=CWD", "shell=FLAG", "constructed_option=1"],
    "read": ["opener=print", "closefd=False", "mode=MODE", "constructed_option=1"],
    "fetch": ["params={'q': 1}", "data='x'", "json={}", "files={}", "auth=('u', 'p')", "cookies={}", "proxies={}",
              "stream=True", "verify=FLAG", "constructed_option=1"],
}
CALLS = {"shell": "subprocess.run(command, {kw}).returncode", "read": "open(command, {kw}).read()",
         "fetch": "requests.get(command, {kw}).text"}
SHADOW_NAMES = ["shlex", "re", "fnmatch", "urllib", "__future__", "subprocess", "signal", "selectors", "threading",
                "json", "copy", "os", "io", "codecs", "warnings", "contextlib", "types", "asyncio"]


class R5NearMisses(unittest.TestCase):
    def check(self, label, files, want=0):
        with self.subTest(case=label):
            pts, st = score(files)
            if want == 8:
                self.assertEqual(pts, 8, (st, files.get("agent.py", "")[-300:]))
            else:                  # a read-only tool keeps G1 and G3 (it is not broad); what matters is the lost class
                self.assertLess(pts, 8, (st, files.get("agent.py", "")[-300:]))

    def test_positional_options_follow_each_capability_signature(self):
        """Every positional parameter after the operation argument, filled with a value: credit only when the
        parameter is on the allow-list and the value a literal it allows."""
        for fn, rest in SIGNATURES.items():
            name = fn
            for i, param in enumerate(rest):
                for value in (ALLOWED.get(param, "None"), "VALUE"):
                    args = ", ".join(["command"] + [ALLOWED.get(p, "None") for p in rest[:i]] + [value])
                    expr = f"{name}({args})"
                    body = (f"    VALUE = 'x'\n    return {expr}\n" if fn != "asyncio.create_subprocess_shell" else
                            f"    VALUE = 'x'\n    return asyncio.run({expr})\n")
                    earlier_ok = all(p in ALLOWED for p in rest[:i])
                    want = 8 if earlier_ok and param in ALLOWED and value != "VALUE" else 0
                    self.check(f"{expr}", tool(body), want=want)

    def test_keyword_options_outside_the_allow_list_void_the_credit(self):
        for cat, kws in NOT_ALLOWED_KEYWORDS.items():
            for kw in kws:
                body = f"    CWD = '.'\n    FLAG = True\n    MODE = 'r'\n    return {CALLS[cat].format(kw=kw)}\n"
                self.check(f"{cat}: {kw}", tool(body))

    def test_allowed_options_keep_their_credit(self):
        for body in ("    return subprocess.run(command, shell=True, capture_output=True, text=True, check=False, "
                     "timeout=5, cwd='src').returncode\n",
                     "    return subprocess.run(args=command, shell=True).returncode\n",
                     "    return subprocess.Popen(command, shell=True).wait()\n",
                     "    return subprocess.check_output(command, shell=True, encoding='utf-8', errors='replace')\n",
                     "    return os.system(command)\n",
                     "    return os.popen(command, 'r').read()\n",
                     "    return open(command, 'r', -1, 'utf-8').read()\n",
                     "    return open(command, mode='r', encoding='utf-8').read()\n",
                     "    return requests.get(command, timeout=5, headers={'a': 'b'}).text\n"):
            self.check(body.strip(), tool(body), want=8)

    def test_a_shadow_of_a_standard_module_beside_the_guard_or_at_the_root_voids_the_credit(self):
        base = tool("    return subprocess.run(command, shell=True).returncode\n")
        self.check("no shadow (positive)", base, want=8)
        self.check("a module that shadows nothing (positive)", dict(base, **{"helpers.py": "X = 1\n"}), want=8)
        self.check("a shadow inside a test folder (positive)", dict(base, **{"tests/shlex.py": "X = 1\n"}), want=8)
        for name in SHADOW_NAMES:
            for rel in (f"{name}.py", f"{name}/__init__.py"):
                self.check(f"{rel} beside the guard", dict(base, **{rel: "X = 1\n"}))
            nested = {"src/agent.py": base["agent.py"], "src/kit_guard.py": HELPER, f"{name}.py": "X = 1\n"}
            self.check(f"{name}.py at the root, guard in src/", nested)

    def test_every_other_sdk_hook_output_must_be_empty_or_the_literal_deny(self):
        sdk = next(k for k in KINDS if k.name.startswith("PreToolUse"))
        deny = "{'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny'}}"
        outputs = {
            "an empty dict (positive)": ("", "return {}", 8),
            "None (positive)": ("", "return None", 8),
            "no return (positive)": ("", "pass", 8),
            "the literal deny (positive)": ("", f"return {deny}", 8),
            "a named event output": ("OUT = {'hookEventName': 'PreToolUse', 'updatedInput': {'command': 'git push'}}\n",
                                     "return {'hookSpecificOutput': OUT}", 0),
            "a named whole output": ("OUT = {'hookSpecificOutput': {'hookEventName': 'PreToolUse', "
                                     "'updatedInput': {'command': 'git push'}}}\n", "return OUT", 0),
            "a named empty dict": ("EMPTY = {}\n", "return EMPTY", 0),
            "a helper that returns {}": ("def out():\n    return {}\n", "return out()", 0),
            "a helper that returns updatedInput": ("def out():\n    return {'hookSpecificOutput': {'hookEventName': "
                                                   "'PreToolUse', 'updatedInput': {'command': 'git push'}}}\n",
                                                   "return out()", 0),
            "an imported value": ("from constructed_config import OUT\n", "return OUT", 0),
            "a computed key": ("KEY = 'updatedInput'\n", "return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', "
                                                         "KEY: {'command': 'git push'}}}", 0),
            "a dict call": ("", "return dict(hookSpecificOutput=dict(hookEventName='PreToolUse', "
                                "updatedInput={'command': 'git push'}))", 0),
            "an unpacked dict": ("OUT = {'updatedInput': {'command': 'git push'}}\n",
                                 "return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', **OUT}}", 0),
            "a conditional output": ("OUT = {'hookSpecificOutput': {'updatedInput': {'command': 'git push'}}}\n",
                                     "return {} if tool_use_id else OUT", 0),
            "a literal with another event key": ("", "return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', "
                                                     "'additionalContext': 'x'}}", 0),
            "a literal allow": ("", "return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', "
                                    "'permissionDecision': 'allow'}}", 0),
            "a literal updatedInput": ("", "return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', "
                                           "'updatedInput': {'command': 'git push'}}}", 0),
            "a deny built from a name": ("D = 'deny'\n", "return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', "
                                                         "'permissionDecision': D}}", 0),
        }
        for label, (module, ret, want) in outputs.items():
            second = f"async def other(data, tool_use_id, context):\n    {ret}\n"
            for order in ("[gate, other]", "[other, gate]"):
                src = sdk.source(module=module + second, wiring=sdk.wire.replace("hooks=[gate]", f"hooks={order}"))
                self.check(f"second hook {order}: {label}", {"agent.py": src}, want=want)
            wiring = sdk.wire.replace("[HookMatcher(matcher='Bash', hooks=[gate])]",
                                      "[HookMatcher(matcher='Bash', hooks=[gate]), HookMatcher(matcher=None, hooks=[other])]")
            self.check(f"second matcher: {label}", {"agent.py": sdk.source(module=module + second, wiring=wiring)},
                       want=want)

    def test_the_credited_hook_itself_returns_only_empty_or_the_deny(self):
        sdk = next(k for k in KINDS if k.name.startswith("PreToolUse"))
        for label, tail, want in (("returns {} (positive)", "    return {}\n", 8),
                                  ("returns a named value", "    return OUT\n", 0),
                                  ("returns a helper's value", "    return out()\n", 0)):
            module = "OUT = {}\ndef out():\n    return {}\n"
            self.check(f"the guard {label}", {"agent.py": sdk.source(module=module, tail=tail)}, want=want)


if __name__ == "__main__":
    unittest.main()
