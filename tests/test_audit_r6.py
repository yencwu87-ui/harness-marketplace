"""Codex round-6 findings on 1.4.6 (R6-01 to R6-04), written as the invariant the audit must hold from 1.4.7 on.

R6-01  the helper removes every backslash-newline pair the way the shell does before any other step, and fails
       closed: it checks the joined and the unjoined forms and refuses when either refuses.
R6-02  any binding of a module object to another name, any attribute store, setattr, delattr or `__dict__` write
       whose base is, or may be, a module, any `sys.modules` write and any importlib or `__import__` use, anywhere in
       the reviewed tree, withholds credit from every helper-credited tool (UNRESOLVED, with the file and line).
R6-03  every node that binds a name is treated like `ast.Assign` in F5's options checks; a binding form the checker
       does not model makes the guard UNRESOLVED.
R6-04  each capability callable has its own exact options, taken from its real signature; an option it does not
       accept, or one outside its written list, is UNRESOLVED.

Fixtures under tests/fixtures/codex_r6 come from Codex's round-6 review of 1.4.6 (see its README). The shipped helper
is written into each throwaway copy, so these tests always run against the helper of the tree under test. Nothing here
uses the network, a model or an installed framework; the runtime checks use constructor stand-ins and constructed
sentinel files in a throwaway folder.
"""
import ast
import importlib.util
import inspect
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import urllib.request
from pathlib import Path

from test_audit_fairness import HELPER, ROOT, audit, guards, points
from test_audit_nearmiss import KINDS, TOOL_HEAD, TOOL_WIRE, score

FIX = ROOT / "tests/fixtures/codex_r6"
KIT_GUARD = ROOT / "kit/shared/kit_guard.py"
SENTINEL = "CONSTRUCTED_R6_SECRET_SENTINEL"
STANDIN = "import sys, types\nm = types.ModuleType('agents')\nm.Agent = lambda **kw: kw\nsys.modules['agents'] = m\n"


def load_kit_guard(path=KIT_GUARD, name="kit_guard_r6"):
    spec = importlib.util.spec_from_file_location(name, path)
    kg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kg)
    return kg


class FixtureCopy:
    """A throwaway copy of one round-6 fixture with the shipped helper beside it (and any extra files)."""

    def __init__(self, name, extra=None):
        self.d = Path(tempfile.mkdtemp())
        shutil.copytree(FIX / name, self.d, dirs_exist_ok=True)
        (self.d / "README.md").unlink(missing_ok=True)
        (self.d / "kit_guard.py").write_text(HELPER)
        for rel, text in (extra or {}).items():
            p = self.d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)

    def __enter__(self):
        return self.d

    def __exit__(self, *a):
        shutil.rmtree(self.d)


def fixture_points(name, **kw):
    with FixtureCopy(name, **kw) as d:
        rep = audit(d)
        return points(rep), {c: g["status"] for c, g in guards(rep).items()}, rep


def run_tool(folder, command, prelude=""):
    """Call the fixture's unchanged `run` tool in a fresh interpreter started in `folder`."""
    code = STANDIN + prelude + f"import agent\nprint(repr(agent.run({command!r})))\n"
    return subprocess.run([sys.executable, "-B", "-c", code], cwd=folder, capture_output=True, text=True)


class R6Acceptance(unittest.TestCase):
    """Codex's acceptance tests (test_r6_acceptance.py), made strict where the finding removes all credit."""

    def test_transitive_module_alias_patch_loses_credit(self):
        pts, st, rep = fixture_points("alias_patch")
        self.assertEqual(pts, 0, st)
        self.assertIn("patch.py:", str(list(guards(rep).values())))       # the file and line are named

    def test_annotated_options_mutation_loses_credit(self):
        pts, st, _ = fixture_points("annotated_opts")
        self.assertEqual(pts, 0, st)

    def test_shell_line_continuation_is_refused(self):
        self.assertTrue(load_kit_guard().refuses("cat .en\\\nv"))

    def test_urlopen_unknown_option_loses_credit(self):
        for name in ("urlopen_headers", "urlopen_redirects"):
            with self.subTest(fixture=name):
                pts, st, _ = fixture_points(name)
                self.assertLess(pts, 8, st)

    def test_paired_controls(self):
        self.assertEqual(fixture_points("plain")[0], 8)
        self.assertEqual(fixture_points("unannotated_opts")[0], 0)
        self.assertEqual(fixture_points("urlopen_timeout")[0], 8)
        kg = load_kit_guard()
        self.assertTrue(kg.refuses("cat .env"))
        self.assertFalse(kg.refuses("cat README.md"))


class R6Runtime(unittest.TestCase):
    """What actually runs, on constructed files in a throwaway folder (no network, no installs)."""

    def test_the_canonical_tool_refuses_a_continued_secret_read(self):
        with FixtureCopy("plain") as d:
            (d / ".env").write_text(SENTINEL + "\n")
            shell = subprocess.run(["/bin/sh", "-c", "cat .en\\\nv"], cwd=d, capture_output=True, text=True)
            self.assertIn(SENTINEL, shell.stdout)                  # the shell joins the word and reads the file
            p = run_tool(d, "cat .en\\\nv")
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertNotIn(SENTINEL, p.stdout)
            self.assertIn("denied", p.stdout)

    def test_the_alias_patch_replaces_the_capability_the_tool_calls(self):
        """Fresh process: importing the fixture makes `subprocess.run` the patch's replacement, so the unchanged
        tool's call is no longer the real capability. The audit must not credit it."""
        with FixtureCopy("alias_patch") as d:
            (d / "id_dsa").write_text(SENTINEL + "\n")
            pre = "import subprocess\nREAL = subprocess.run\n"
            code = STANDIN + pre + "import agent\nprint(agent.subprocess.run is REAL)\nprint(agent.run('echo ordinary'))\n"
            p = subprocess.run([sys.executable, "-B", "-c", code], cwd=d, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.splitlines()[0], "False")
            self.assertIn(SENTINEL, p.stdout)
            self.assertEqual(audit_points(d), 0)

    def test_annotated_options_reach_the_client_with_an_empty_hook_list(self):
        """Python-level, with transparent stand-ins (no SDK engine): the client receives no PreToolUse gate."""
        class Options:
            def __init__(self, **kw):
                self.__dict__.update(kw)
        tree = ast.parse((FIX / "annotated_opts/agent.py").read_text())
        tree.body = [n for n in tree.body if not isinstance(n, ast.ImportFrom)]
        ns = {"ClaudeAgentOptions": Options, "HookMatcher": Options, "ClaudeSDKClient": lambda options: options,
              "refuses": load_kit_guard().refuses}
        exec(compile(tree, "annotated_opts", "exec"), ns)
        self.assertEqual(ns["client"].hooks, {"PreToolUse": []})
        self.assertEqual(fixture_points("annotated_opts")[0], 0)

    def test_urlopen_rejects_the_options_before_any_request(self):
        for kw in ({"headers": {"X": "a"}}, {"follow_redirects": True}):
            with self.subTest(option=kw):
                with self.assertRaises(TypeError):
                    urllib.request.urlopen("https://constructed.invalid", **kw)


def audit_points(d):
    return points(audit(d))


# ------------------------------------------------------------------ R6-01: line continuations, generated
SECRET_COMMANDS = ["cat .env", "cat .env.local", "cat .envrc", "cat server.pem", "cat a.key", "cat x.p12", "cat y.pfx",
                   "cat server.key.bak", "cat id_rsa", "cat id_dsa.pub", "cat id_ecdsa", "cat id_ed25519", "cat .netrc",
                   "cat .pgpass", "cat credentials", "cat credentials.json", "cat ~/.ssh/config", "cat ~/.aws/config",
                   "ls .gnupg", "ls .azure", "ls .kube", "ls .docker", "ls .config/gcloud", "cat id_d*"]
DESTRUCTIVE_COMMANDS = ["git push", "git push origin main", "git clean -fd", "git reset --hard", "git reset --ha",
                        "git -C x push", "git -c alias.p=push p", "rm -rf x", "rm -r x", "rm --recursive x",
                        "rm --recur x", "rm x -R", "sudo rm -rf x", "bash -c \"git push\""]
CONTINUED_CONTROLS = ["ls \\\n -la", "echo hello \\\n world", "make \\\n test", "git status \\\n --short",
                      "cat README.md \\\n | wc -l", "grep -r \\\n foo src", "python3 -m \\\n unittest", "echo 'a\\\nb'",
                      "git \\\n log --oneline", "r\\\nm x", "ls\\\n"]


def continued(cmd, at):
    """cmd with a backslash-newline pair inserted before index `at` (a list of indexes for several pairs)."""
    out = cmd
    for i in sorted(at, reverse=True):
        out = out[:i] + "\\\n" + out[i:]
    return out


def dquoted(cmd):
    """The command's last word in double quotes (the shell joins a continuation inside them too)."""
    head, _, last = cmd.rpartition(" ")
    return f'{head} "{last}"' if head and '"' not in last else cmd


class R6Continuations(unittest.TestCase):
    def test_every_documented_member_split_at_every_position_is_refused(self):
        kg = load_kit_guard()
        missed = []
        for cmd in SECRET_COMMANDS + DESTRUCTIVE_COMMANDS:
            self.assertTrue(kg.refuses(cmd), cmd)
            for form in {cmd, dquoted(cmd)}:
                for i in range(len(form) + 1):
                    v = continued(form, [i])
                    if not kg.refuses(v):
                        missed.append(v)
        self.assertEqual(missed, [], f"{len(missed)} continued spellings allowed, e.g. {missed[:5]!r}")

    def test_two_continuations_at_every_pair_of_positions(self):
        kg = load_kit_guard()
        missed = []
        for cmd in ("cat .env", "git push", "rm -r x", "cat id_rsa"):
            for i in range(len(cmd) + 1):
                for j in range(i, len(cmd) + 1):
                    v = continued(cmd, [i, j])
                    if not kg.refuses(v):
                        missed.append(v)
        self.assertEqual(missed, [], missed[:5])

    def test_the_shell_joins_what_the_helper_now_joins(self):
        """Differential: /bin/sh prints the words it would run (printf in front, nothing executed); the words joined
        back equal the original command, and the helper refuses every such spelling."""
        kg = load_kit_guard()
        for cmd in ("cat .env", 'cat ".env"', "git push", "rm --recursive x", "ls .config/gcloud"):
            for i in range(len(cmd) + 1):
                v = continued(cmd, [i])
                with self.subTest(command=v):
                    p = subprocess.run(["/bin/sh", "-c", "printf '%s\\n' " + v], capture_output=True, text=True)
                    self.assertEqual(p.stdout.split("\n")[:-1], cmd.replace('"', "").split(" "))
                    self.assertTrue(kg.refuses(v))

    def test_ordinary_continued_commands_stay_allowed(self):
        kg = load_kit_guard()
        for v in CONTINUED_CONTROLS:
            with self.subTest(command=v):
                self.assertFalse(kg.refuses(v))

    def test_single_quotes_and_tool_inputs_fail_closed(self):
        """Inside single quotes the shell keeps the pair, but the joined form is refused too (fail closed); a dict or
        argument-vector input is joined the same way."""
        kg = load_kit_guard()
        for v in ("cat '.en\\\nv'", {"command": "cat .en\\\nv"}, ["cat", ".en\\\nv"], ["git", "pu\\\nsh"],
                  {"file_path": "/x/.ss\\\nh/id_rsa"}, ("bash", "-c", "git pu\\\nsh")):
            with self.subTest(value=v):
                self.assertTrue(kg.refuses(v))


# ------------------------------------------------------------------ R6-02: module handles in any file, generated
SHELL_TOOL = {"agent.py": TOOL_HEAD + "from kit_guard import refuses\nimport patch\ndef run(command):\n"
              "    if refuses(command):\n        return 'denied'\n"
              "    return subprocess.run(command, shell=True).returncode\n" + TOOL_WIRE}
REPLACEMENT = "def replacement(*a, **k):\n    return None\n"
# A second module in the tree: each binds a module object to another name, stores through a (possible) module, or
# reaches modules through sys.modules, importlib or __import__.
MODULE_CHANGES = {
    "a plain alias": "import subprocess\nfirst = subprocess\n",
    "a transitive alias and a store": "import subprocess\nfirst = subprocess\nsecond = first\nsecond.run = replacement\n",
    "an annotated alias": "import subprocess\nfirst: object = subprocess\nfirst.run = replacement\n",
    "a walrus alias": "import subprocess\nif (first := subprocess):\n    first.run = replacement\n",
    "a for target": "import subprocess\nfor first in (subprocess,):\n    first.run = replacement\n",
    "a with target": "import subprocess, contextlib\nwith contextlib.nullcontext(subprocess) as first:\n"
                     "    first.run = replacement\n",
    "tuple unpacking": "import subprocess\nfirst, other = subprocess, 1\nfirst.run = replacement\n",
    "list unpacking": "import subprocess\n[first] = [subprocess]\nfirst.run = replacement\n",
    "a starred target": "import subprocess\n*first, = (subprocess,)\nfirst[0].run = replacement\n",
    "a chained assignment": "import subprocess\na = b = subprocess\nb.run = replacement\n",
    "a default argument": "import subprocess\ndef f(m=subprocess):\n    m.run = replacement\nf()\n",
    "an argument": "import subprocess\ndef f(m):\n    m.run = replacement\nf(subprocess)\n",
    "a keyword argument": "import subprocess\ndef f(m=None):\n    m.run = replacement\nf(m=subprocess)\n",
    "a returned module": "import subprocess\ndef get():\n    return subprocess\nget().run = replacement\n",
    "a lambda": "import subprocess\nget = lambda: subprocess\nget().run = replacement\n",
    "a container": "import subprocess\nMODS = [subprocess]\nMODS[0].run = replacement\n",
    "a dict value": "import subprocess\nMODS = {'s': subprocess}\nMODS['s'].run = replacement\n",
    "a class attribute": "import subprocess\nclass C:\n    m = subprocess\nC.m.run = replacement\n",
    "a global in a function": "import subprocess\ndef f():\n    global first\n    first = subprocess\nf()\n",
    "an import alias and a store": "import subprocess as first\nfirst.run = replacement\n",
    "a from-imported module and a store": "from os import path as p\np.join = replacement\n",
    "a dotted import and a store": "import os.path\nos.path.join = replacement\n",
    "an augmented store": "import subprocess\nsubprocess.TIMEOUT_EXTRA = 0\nsubprocess.TIMEOUT_EXTRA += 1\n",
    "a deletion": "import subprocess\ndel subprocess.run\n",
    "setattr": "import subprocess\nsetattr(subprocess, 'run', replacement)\n",
    "delattr": "import subprocess\ndelattr(subprocess, 'getoutput')\n",
    "a __dict__ write": "import subprocess\nsubprocess.__dict__['run'] = replacement\n",
    "a vars() write": "import subprocess\nvars(subprocess)['run'] = replacement\n",
    "a sys.modules store": "import sys\nsys.modules['subprocess'].run = replacement\n",
    "a sys.modules write": "import sys, types\nsys.modules['subprocess'] = types.SimpleNamespace(run=replacement)\n",
    "a sys.modules alias": "import sys\nmods = sys.modules\nmods['subprocess'].run = replacement\n",
    "importlib": "import importlib\nimportlib.import_module('subprocess').run = replacement\n",
    "importlib alone": "import importlib\nX = importlib\n",
    "from importlib": "from importlib import import_module\nimport_module('subprocess').run = replacement\n",
    "__import__": "__import__('subprocess').run = replacement\n",
    "__import__ alone": "M = __import__('json')\n",
    "getattr of sys": "import sys\ngetattr(sys, 'modules')['subprocess'].run = replacement\n",
    "an unresolvable call result": "import pkgutil\nx = pkgutil.resolve_name('subprocess')\nx.run = replacement\n",
    "a store on a call": "import pkgutil\npkgutil.resolve_name('subprocess').run = replacement\n",
    "a for target over objects": "import gc\nfor o in gc.get_objects():\n    if getattr(o, '__name__', '') == 'subprocess':\n"
                                 "        o.run = replacement\n",
    "a function's globals": "import subprocess\nsubprocess.run.__globals__['Popen'] = replacement\n",
    "a builtin's module": "print.__self__.open = replacement\n",
    "sys.path": "import sys\nsys.path.insert(0, 'constructed')\n",
    "a mutator through a module": "import subprocess\nsubprocess.__all__.append('x')\n",
    "an attribute of a module bound": "import subprocess\nrun = subprocess.run\n",
    "unittest.mock": "from unittest import mock\nmock.patch('subprocess.run', replacement).start()\n",
    "mock.patch.object": "import subprocess\nfrom unittest import mock\nmock.patch.object(subprocess, 'run', replacement).start()\n",
}
# Ordinary code in a second module: none of it binds or changes a module.
MODULE_CONTROLS = {
    "a constant": "X = 1\n",
    "a class with instance stores": "class C:\n    def __init__(self):\n        self.x = 1\n",
    "a dict and list": "D = {}\nD['k'] = 1\nL = []\nL.append(1)\n",
    # 1.4.9 (R8-02): a store on a plain parameter now withholds credit; a store on self in a closed class does not
    "a store on self": "class Config:\n    def configure(self):\n        self.debug = True\n",
    "an environment store": "import os\nos.environ['CONSTRUCTED'] = '1'\n",
    "an isinstance test": "import subprocess\ndef ok(x):\n    return isinstance(x, subprocess.CompletedProcess)\n",
    "an os.walk prune": "import os\nfor dirpath, dirnames, files in os.walk('.'):\n    dirnames[:] = []\n",
    "module calls": "import json, subprocess\nOUT = json.dumps({'a': 1})\ndef ls():\n    return subprocess.run(['ls'])\n",
    "an exception name": "try:\n    X = 1\nexcept ValueError as e:\n    e.note = 'x'\n",
}


class R6ModuleHandles(unittest.TestCase):
    def check(self, label, files, want):
        with self.subTest(case=label):
            pts, st = score(files)
            if want == 8:
                self.assertEqual(pts, 8, (st, files.get("patch.py", "")))
            else:
                self.assertEqual(pts, 0, (st, files.get("patch.py", "")))

    def test_a_module_handle_in_an_imported_file_withholds_credit(self):
        for label, text in MODULE_CHANGES.items():
            self.check(f"imported: {label}", dict(SHELL_TOOL, **{"patch.py": REPLACEMENT + text}), want=0)

    def test_a_module_handle_in_a_file_nobody_imports_withholds_credit(self):
        tool = dict(SHELL_TOOL, **{"agent.py": SHELL_TOOL["agent.py"].replace("import patch\n", "")})
        for label, text in MODULE_CHANGES.items():
            self.check(f"not imported: {label}", dict(tool, **{"lib/other.py": REPLACEMENT + text}), want=0)

    def test_a_module_handle_in_the_tool_module_withholds_credit(self):
        for label, text in MODULE_CHANGES.items():
            body = SHELL_TOOL["agent.py"].replace("import patch\n", REPLACEMENT + text)
            self.check(f"in agent.py: {label}", dict(SHELL_TOOL, **{"agent.py": body}), want=0)

    def test_ordinary_code_in_another_module_keeps_credit(self):
        self.check("no second module", dict(SHELL_TOOL, **{"patch.py": "X = 1\n"}), want=8)
        for label, text in MODULE_CONTROLS.items():
            self.check(f"control: {label}", dict(SHELL_TOOL, **{"patch.py": text}), want=8)

    def test_the_unresolved_reason_names_the_file_and_line(self):
        files = dict(SHELL_TOOL, **{"patch.py": REPLACEMENT + MODULE_CHANGES["a transitive alias and a store"]})
        files["kit_guard.py"] = HELPER
        from test_audit_fairness import Repo
        with Repo(files) as d:
            text = str([c for c in audit(d)["checks"] if c["id"] in ("G1", "G2", "G3")])
        self.assertIn("patch.py:", text)


# ------------------------------------------------------------------ R6-03: every binding form of the options
SDK = next(k for k in KINDS if k.name.startswith("PreToolUse"))
CALL = SDK.wire.split(" = ", 1)[1].strip()
PRE = "from claude_agent_sdk import ClaudeSDKClient\nimport dataclasses\n"
CLEAR = "opts.hooks['PreToolUse'].clear()\n"
# The options bound by each form, then changed: none may keep credit.
MUTATIONS = {
    "clear": "{n}.hooks['PreToolUse'].clear()\n",
    "append": "{n}.hooks['PreToolUse'].append(HookMatcher(matcher='Bash', hooks=[]))\n",
    "replace the dict": "{n}.hooks = {{}}\n",
    "replace the list": "{n}.hooks['PreToolUse'] = []\n",
    "an alias then clear": "alias = {n}\nalias.hooks['PreToolUse'].clear()\n",
    "dataclasses.replace": "{n} = dataclasses.replace({n}, hooks={{}})\n",
    "del an item": "del {n}.hooks['PreToolUse']\n",
    "setattr": "setattr({n}, 'hooks', {{}})\n",
}
BINDINGS = {          # form, then the name the mutation uses
    "assignment": ("opts = {c}\n", "opts"),
    "annotated assignment": ("opts: ClaudeAgentOptions = {c}\n", "opts"),
    "annotated with another type": ("opts: object = {c}\n", "opts"),
}
UNMODELLED = {        # forms the checker does not model: UNRESOLVED even with nothing after them
    "walrus": "if (opts := {c}):\n    pass\n",
    "for target": "for opts in [{c}]:\n    pass\n",
    "with target": "with {c} as opts:\n    pass\n",
    "tuple unpacking": "opts, n = {c}, 1\n",
    "list unpacking": "[opts] = [{c}]\n",
    "chained assignment": "first = opts = {c}\n",
    "attribute target": "class Cfg:\n    pass\nCfg.opts = {c}\n",
    "subscript target": "CFG = {{}}\nCFG['opts'] = {c}\n",
    "a list element": "ALL = [{c}]\n",
    "a dict value": "ALL = {{'a': {c}}}\n",
    "a lambda": "make = lambda: {c}\n",
    "another call": "def build(o):\n    return o\nopts = build({c})\n",
    "a conditional expression": "opts = {c} if True else None\n",
    "a default argument": "def start(o={c}):\n    return ClaudeSDKClient(options=o)\n",
    "a keyword of a non-SDK call": "def build(**k):\n    return k\nopts = build(options={c})\n",
}
SECOND_BINDINGS = {   # a second binding of the same name, in every binding form
    "augmented": "opts += 1\n",
    "plain": "opts = None\n",
    "annotated": "opts: object = None\n",
    "bare annotation": "opts: object\n",
    "walrus": "if (opts := None):\n    pass\n",
    "for": "for opts in []:\n    pass\n",
    "with": "import contextlib\nwith contextlib.nullcontext() as opts:\n    pass\n",
    "tuple": "opts, x = None, 1\n",
    "except": "try:\n    pass\nexcept Exception as opts:\n    pass\n",
    "match": "match 1:\n    case opts:\n        pass\n",
    "import": "import opts\n",
    "from import": "from constructed import opts\n",
    "global": "def f():\n    global opts\n    opts = None\n",
    "nonlocal": "def f():\n    opts = None\n    def g():\n        nonlocal opts\n        opts = 1\n",
    "del": "del opts\n",
    "def": "def opts():\n    pass\n",
    "class": "class opts:\n    pass\n",
    "comprehension": "X = [opts for opts in ()]\n",
}


class R6BindingForms(unittest.TestCase):
    def check(self, label, wiring, want, extra=None):
        with self.subTest(case=label):
            files = {"agent.py": SDK.source(module=PRE, wiring=wiring)}
            files.update(extra or {})
            pts, st = score(files)
            self.assertEqual(pts, want, (st, wiring))

    def test_positives_keep_credit(self):
        self.check("assignment", f"opts = {CALL}\n", 8)
        self.check("annotated assignment", f"opts: ClaudeAgentOptions = {CALL}\n", 8)
        self.check("annotated, passed to the client", f"opts: ClaudeAgentOptions = {CALL}\n"
                                                      "client = ClaudeSDKClient(options=opts)\n", 8)
        self.check("inline in the client", f"client = ClaudeSDKClient(options={CALL})\n", 8)
        self.check("returned", f"def make():\n    return {CALL}\n", 8)

    def test_every_modelled_binding_then_a_change_loses_credit(self):
        for bl, (form, name) in BINDINGS.items():
            self.check(f"{bl} (positive)", form.format(c=CALL), 8)
            for ml, change in MUTATIONS.items():
                self.check(f"{bl}, then {ml}", form.format(c=CALL) + change.format(n=name), 0)

    def test_an_unmodelled_binding_form_is_unresolved(self):
        for label, form in UNMODELLED.items():
            self.check(label, form.format(c=CALL), 0)

    def test_a_second_binding_of_the_name_in_any_form_is_unresolved(self):
        for bl, (form, _) in BINDINGS.items():
            for label, second in SECOND_BINDINGS.items():
                self.check(f"{bl}, then {label}", form.format(c=CALL) + second, 0)

    def test_the_options_changed_through_the_client_or_another_module(self):
        self.check("client.options", f"opts = {CALL}\nclient = ClaudeSDKClient(options=opts)\n"
                                     "client.options.hooks['PreToolUse'].clear()\n", 0)
        for label, text in (("from agent import opts", "from agent import opts\nopts.hooks['PreToolUse'].clear()\n"),
                            ("import agent", "import agent\nagent.opts.hooks['PreToolUse'].clear()\n"),
                            ("from agent import *", "from agent import *\nopts.hooks['PreToolUse'].clear()\n")):
            for form in (f"opts = {CALL}\n", f"opts: ClaudeAgentOptions = {CALL}\n"):
                self.check(f"other.py: {label}", form, 0, extra={"other.py": text})


# ------------------------------------------------------------------ R6-04: per-callable options, generated
OPTIONS = {"timeout": "5", "headers": "{'X': 'a'}", "allow_redirects": "True", "follow_redirects": "True",
           "verify": "True", "method": "'GET'"}
# What each fetch callable accepts of the written list, from its signature (stdlib checked below with inspect;
# requests 2.32 and httpx 0.28 from their documented signatures, since neither is installed here).
_REQ = {"timeout", "headers", "allow_redirects", "verify"}
_HTTPX = {"timeout", "headers", "follow_redirects", "verify"}
ACCEPTS = {
    **{f"requests.{m}(command, {{kw}})": _REQ for m in ("get", "head", "options", "delete", "post", "put", "patch")},
    "requests.request('GET', command, {kw})": _REQ,
    **{f"requests.Session().{m}(command, {{kw}})": _REQ for m in ("get", "post")},
    **{f"httpx.{m}(command, {{kw}})": _HTTPX for m in ("get", "head", "options", "delete", "post", "put", "patch")},
    "httpx.request('GET', command, {kw})": _HTTPX,
    **{f"httpx.Client().{m}(command, {{kw}})": _HTTPX - {"verify"} for m in ("get", "post")},
    "urllib.request.urlopen(command, {kw})": {"timeout"},
    "urllib.request.Request(command, {kw})": {"headers", "method"},
    "urllib.request.urlretrieve(command, {kw})": set(),
}


def fetch_tool(expr):
    return {"agent.py": TOOL_HEAD + "import httpx, urllib.request\nfrom kit_guard import refuses\n"
            "def run(command):\n    if refuses(command):\n        return 'denied'\n"
            f"    return {expr}\n" + TOOL_WIRE}


class R6FetchOptions(unittest.TestCase):
    def test_the_stdlib_table_matches_the_real_signatures(self):
        for fn, key in ((urllib.request.urlopen, "urllib.request.urlopen(command, {kw})"),
                        (urllib.request.Request, "urllib.request.Request(command, {kw})"),
                        (urllib.request.urlretrieve, "urllib.request.urlretrieve(command, {kw})")):
            params = set(inspect.signature(fn).parameters)
            self.assertEqual({o for o in OPTIONS if o in params}, ACCEPTS[key], key)

    def test_each_option_keeps_credit_only_where_the_callable_takes_it(self):
        for expr, accepted in ACCEPTS.items():
            for opt, value in OPTIONS.items():
                kw = f"{opt}={value}"
                want = 8 if opt in accepted else 0
                with self.subTest(call=expr.format(kw=kw)):
                    pts, st = score(fetch_tool(expr.format(kw=kw)))
                    if want == 8:
                        self.assertEqual(pts, 8, st)
                    else:
                        self.assertLess(pts, 8, st)
                        self.assertNotEqual(st.get("G2"), "VERIFIED", st)

    def test_a_callable_outside_the_table_earns_nothing(self):
        for expr in ("aiohttp.request('GET', command)", "urllib3.request('GET', command)",
                     "http.client.HTTPConnection(command)", "requests.Session(trust_env=False).get(command)",
                     "client.get(command)"):
            with self.subTest(call=expr):
                body = expr if not expr.startswith("client") else "client.get(command)"
                tool = fetch_tool(body)
                tool["agent.py"] = tool["agent.py"].replace("import httpx,", "import aiohttp, urllib3, http.client, httpx,")
                if expr.startswith("client"):
                    tool["agent.py"] = tool["agent.py"].replace("def run(", "client = httpx.Client()\ndef run(")
                pts, st = score(tool)
                self.assertNotEqual(st.get("G2"), "VERIFIED", st)


if __name__ == "__main__":
    unittest.main()
