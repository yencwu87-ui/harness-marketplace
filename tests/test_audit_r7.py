"""Codex round-7 findings on 1.4.7 (R7-01 to R7-04, and the brace boundary), written as the invariant the audit must
hold from 1.4.8 on.

R7-01  a value that is or may be a module (a name bound by import, a name imported with `from` that is not a class,
       an attribute of a module, or what getattr returns for one) may only be the object of an attribute read or
       call (`m.attr`, `m.attr(...)`), an item read, or a test or comparison. Assigning or binding it, passing it as
       an argument, returning it, putting it in a container or using it as a key, holding it as a class or instance
       attribute, or making it the target of getattr, hasattr, setattr, delattr, vars or `__dict__` withholds credit
       tree-wide (UNRESOLVED, with the file and line). The attribute of an outside module may also be passed to an
       outside callable not on the hand-on list in the same expression (`stdout=subprocess.PIPE`).
R7-02  credited SDK options are bound once, at module level or as a function local, by a single plain or annotated
       assignment; a class namespace, an instance attribute, a default or a container makes the guard UNRESOLVED.
R7-03  each capability's allowed options are its own written list, and no written option, alone or with another
       written one, can make the real callable raise (checked here by calling it in a harmless way).
R7-04  a capitalised name imported with `from` from outside the repo, not renamed to a capitalised name from a
       lower-case one, is taken to be a class everywhere (the written exception, kept bounded).
Braces the helper expands each brace group in a command (bounded) and refuses when any alternative, or the words
       the shell would produce, refuse; a group too large or nested too deep is refused outright.

Fixtures under tests/fixtures/codex_r7 come from Codex's round-7 review of 1.4.7 (see its README). The shipped helper
is written into each throwaway copy. Nothing here uses the network, a model or an installed framework; the runtime
checks use constructor stand-ins, constructed sentinel files and harmless commands (`true`) in a throwaway folder.
"""
import ast
import asyncio
import codecs
import itertools
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import HELPER, ROOT, Repo, audit, guards, load_audit, points
from test_audit_nearmiss import KINDS, TOOL_HEAD, TOOL_WIRE, score
from test_audit_r6 import STANDIN, load_kit_guard

FIX = ROOT / "tests/fixtures/codex_r7"
SENTINEL = "CONSTRUCTED_R7_SECRET_SENTINEL"


class FixtureCopy:
    def __init__(self, name):
        self.d = Path(tempfile.mkdtemp())
        shutil.copytree(FIX / name, self.d, dirs_exist_ok=True)
        (self.d / "README.md").unlink(missing_ok=True)
        (self.d / "kit_guard.py").write_text(HELPER)

    def __enter__(self):
        return self.d

    def __exit__(self, *a):
        shutil.rmtree(self.d)


def fixture_points(name):
    with FixtureCopy(name) as d:
        rep = audit(d)
        return points(rep), {c: g["status"] for c, g in guards(rep).items()}, rep


class R7Acceptance(unittest.TestCase):
    """Codex's acceptance tests (test_r7_acceptance.py), strict where the finding removes all credit."""

    def test_getattr_module_hand_on_loses_credit(self):
        for n in ("getattr_hand_on", "getattr_binding", "getattr_default"):
            with self.subTest(shape=n):
                pts, st, rep = fixture_points(n)
                self.assertEqual(pts, 0, st)
                self.assertIn("patch.py:", str(list(guards(rep).values())))

    def test_class_options_mutation_loses_credit(self):
        for n in ("class_opts", "class_annotated_opts"):
            with self.subTest(shape=n):
                pts, st, _ = fixture_points(n)
                self.assertEqual(pts, 0, st)

    def test_supported_class_argument_keeps_credit(self):
        self.assertEqual(fixture_points("class_to_repo_function")[0], 8)

    def test_check_output_rejected_options_lose_credit(self):
        for n in ("check_output_check", "check_output_capture"):
            with self.subTest(shape=n):
                pts, st, _ = fixture_points(n)
                self.assertEqual(pts, 0, st)

    def test_controls(self):
        for n in ("plain", "class_to_outside_function", "check_output_plain", "plain_opts_control"):
            with self.subTest(control=n):
                self.assertEqual(fixture_points(n)[0], 8)
        for n in ("direct_control", "list_item", "dict_key", "param_shadow", "getattr_module_mutator",
                  "getattr_path_append", "capital_module"):
            with self.subTest(control=n):
                self.assertEqual(fixture_points(n)[0], 0)

    def test_the_brace_boundary(self):
        kg = load_kit_guard()
        for v in ("git {push,status}", "g{it,xx} push", "r{m,x} -rf disposable", "cat .e{n,x}v"):
            with self.subTest(value=v):
                self.assertTrue(kg.refuses(v))


class R7Runtime(unittest.TestCase):
    """What actually runs, on constructed files in a throwaway folder (no network, no installs)."""

    def test_the_getattr_hand_on_replaces_the_capability_the_tool_calls(self):
        for n in ("getattr_hand_on", "getattr_binding", "getattr_default"):
            with self.subTest(shape=n), FixtureCopy(n) as d:
                (d / "id_dsa").write_text(SENTINEL + "\n")
                code = STANDIN + "import agent\nprint(repr(agent.run('echo ordinary')))\n"
                p = subprocess.run([sys.executable, "-B", "-c", code], cwd=d, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(SENTINEL, p.stdout)            # the threat is real; the audit must not credit it

    def test_class_held_options_reach_the_client_with_an_empty_hook_list(self):
        for n in ("class_opts", "class_annotated_opts"):
            with self.subTest(shape=n), FixtureCopy(n) as d:
                stand = ("import sys, types\nm = types.ModuleType('claude_agent_sdk')\n"
                         "class O:\n    def __init__(self, **kw):\n        self.__dict__.update(kw)\n"
                         "m.ClaudeAgentOptions = O\nm.HookMatcher = O\n"
                         "m.ClaudeSDKClient = lambda options: options\nsys.modules['claude_agent_sdk'] = m\n")
                code = stand + "import agent\nprint(agent.client.hooks)\n"
                p = subprocess.run([sys.executable, "-B", "-c", code], cwd=d, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout.strip(), "{'PreToolUse': []}")

    def test_check_output_rejects_the_options(self):
        for kw, err in (({"check": False}, "check argument not allowed"),
                        ({"capture_output": True}, "capture_output")):
            with self.subTest(option=kw), self.assertRaises(ValueError) as cm:
                subprocess.check_output("true", shell=True, **kw)
            self.assertIn(err, str(cm.exception))


# ------------------------------------------------------------------ R7-01, R7-04: every use of a module value
TOOL = {"agent.py": TOOL_HEAD + "from kit_guard import refuses\nimport patch\ndef run(command):\n"
        "    if refuses(command):\n        return 'denied'\n"
        "    return subprocess.run(command, shell=True).returncode\n" + TOOL_WIRE,
        "lib.py": "import subprocess\nFLAG = 1\n"}
# Where a value that is or may be a module comes from: (prelude, expression, class). "name": a module name or a
# repo module's module; "attr": an attribute of an outside module (may be a module); "getattr": getattr's target is a
# module value, so it withholds credit itself, whatever the use.
SOURCES = {
    "an imported module": ("import subprocess\n", "subprocess", "name"),
    "an import alias": ("import subprocess as sp\n", "sp", "name"),
    "a dotted import's root": ("import os.path\n", "os", "name"),
    "a from-imported outside module": ("from os import path\n", "path", "name"),
    "a lower-case module renamed capitalised": ("from os import path as Path\n", "Path", "name"),
    "a repo module": ("import lib\n", "lib", "name"),
    "a repo module's module": ("import lib\n", "lib.subprocess", "name"),
    "a module from-imported through a repo module": ("from lib import subprocess as sp\n", "sp", "name"),
    "an outside module's attribute": ("import os\n", "os.path", "attr"),
    "getattr of a repo module": ("import lib\n", "getattr(lib, 'subprocess')", "getattr"),
    "getattr of an outside module": ("import os\n", "getattr(os, 'path')", "getattr"),
    "nested getattr": ("import lib\n", "getattr(getattr(lib, 'subprocess'), 'run')", "getattr"),
    "getattr then an attribute": ("import lib\n", "getattr(lib, 'subprocess').run", "getattr"),
    "getattr of an attribute": ("import os\n", "getattr(os.path, 'sep')", "getattr"),
}
# Uses that withhold credit for every source.
FORBIDDEN = {
    "assigned": "x = {m}\n",
    "annotated": "x: object = {m}\n",
    "augmented": "x = 1\nx += {m}\n",
    "walrus": "if (x := {m}):\n    pass\n",
    "chained": "a = b = {m}\n",
    "unpacked": "a, b = {m}, 1\n",
    "a for target over a display": "for x in ({m},):\n    pass\n",
    "a with target": "with {m} as x:\n    pass\n",
    "a default": "def f(x={m}):\n    pass\n",
    "a keyword-only default": "def f(*, x={m}):\n    pass\n",
    "a lambda default": "f = lambda x={m}: x\n",
    "a lambda body": "f = lambda: {m}\n",
    "returned": "def f():\n    return {m}\n",
    "yielded": "def f():\n    yield {m}\n",
    "an argument to a repo function": "def change(x):\n    pass\nchange({m})\n",
    "a keyword argument to a repo function": "def change(x=None):\n    pass\nchange(x={m})\n",
    "a starred argument": "def change(*x):\n    pass\nchange(*[{m}])\n",
    "an argument to a repo method": "class K:\n    def change(self, x):\n        pass\nK().change({m})\n",
    "an argument to a repo class": "class K:\n    def __init__(self, x):\n        pass\nK({m})\n",
    "an argument to a hand-on callable": "import functools\nfunctools.partial(print, {m})\n",
    "an argument to an unresolved method": "def go(obj):\n    obj.take({m})\n",
    "getattr's target": "getattr({m}, 'sep')\n",
    "hasattr's target": "hasattr({m}, 'sep')\n",
    "setattr's target": "setattr({m}, 'X', 1)\n",
    "delattr's target": "delattr({m}, 'X')\n",
    "vars": "vars({m})\n",
    "__dict__": "{m}.__dict__\n",
    "a list": "L = [{m}]\n",
    "a tuple statement": "({m}, 1)\n",
    "a set": "S = {{{m}}}\n",
    "a dict value": "D = {{'k': {m}}}\n",
    "a dict key": "D = {{{m}: 1}}\n",
    "a subscript key store": "D = {{}}\nD[{m}] = 1\n",
    "a subscript key read": "D = {{}}\nD[{m}]\n",
    "a class attribute": "class K:\n    x = {m}\n",
    "an instance attribute": "class K:\n    def __init__(self):\n        self.x = {m}\n",
    "an attribute target": "class K:\n    pass\nK.x = {m}\n",
    "a comprehension element": "L = [{m} for _ in range(1)]\n",
    "a conditional expression bound": "x = {m} if True else None\n",
    "an or-expression bound": "x = None or {m}\n",
    "a global in a function": "def f():\n    global x\n    x = {m}\n",
}
# Uses of an outside module's attribute inside an outside call (the same expression): allowed for "attr" sources only.
OUTSIDE_READS = {
    "print": "print({m})\n",
    "an outside keyword": "subprocess.run(['true'], stdout={m})\n",
    "isinstance's class tuple": "isinstance(1, ({m}, int))\n",
}
# Uses allowed for "name" and "attr" sources (a getattr source withholds credit whatever its use).
ALLOWED = {
    "a call": "{m}.f()\n",
    "a call's result bound": "x = {m}.f()\n",
    "an attribute read in a test": "if {m}.FLAG:\n    pass\n",
    "an attribute compared": "x = {m}.FLAG == 1\n",
    "an item read": "x = {m}.FLAG[0]\n",
    "an f-string": "x = f'{{{m}.FLAG}}'\n",
    "a loop over an attribute": "for x in {m}.FLAG:\n    pass\n",
    "a compared module": "x = {m} is None\n",
    "a tested module": "if {m}:\n    pass\n",
    "an except clause": "try:\n    pass\nexcept {m}.Error:\n    pass\n",
    "a base class": "class K({m}.Base):\n    pass\n",
    "a decorator": "@{m}.deco\ndef f():\n    pass\n",
    "an assert": "assert {m}.FLAG\n",
    "an annotation": "x: {m}.T = 1\n",
}
# R7-04: a capitalised class imported with `from` from outside the repo: any use keeps credit (stores on it do not).
CLASS_USES = {
    "an argument to a repo function": "def consume(cls):\n    return 1\nconsume(Counter)\n",
    "an argument to a local function": "def outer():\n    def consume(cls):\n        return 1\n    return consume(Counter)\n",
    "an argument to a repo method": "class K:\n    def take(self, cls):\n        return 1\nK().take(Counter)\n",
    "an argument to an outside function": "print(Counter)\n",
    "a keyword argument": "def consume(cls=None):\n    return 1\nconsume(cls=Counter)\n",
    "bound": "C = Counter\n",
    "in a container": "TYPES = [Counter, int]\n",
    "returned": "def kind():\n    return Counter\n",
    "a default": "def make(factory=Counter):\n    return factory()\n",
    "a renamed class": "def consume(cls):\n    return 1\nconsume(C2)\n",
}
CLASS_PRELUDE = "from collections import Counter\nfrom collections import OrderedDict as C2\n"
CLASS_NOT_EXEMPT = {    # lower-case names, or a lower-case module renamed capitalised: still module values
    "a lower-case from-import": ("from os import path\n", "path"),
    "renamed capitalised": ("from os import path as Path\n", "Path"),
    "renamed capitalised from a class-like module name": ("from os import sep as Sep\n", "Sep"),
}


class R7ModuleValues(unittest.TestCase):
    def check(self, label, text, want, place="patch.py"):
        files = dict(TOOL)
        if place == "agent.py":
            files["agent.py"] = files["agent.py"].replace("import patch\n", text)
        else:
            files[place] = text
        with self.subTest(case=label, place=place):
            pts, st = score(files)
            self.assertEqual(pts, want, (st, text))

    def test_every_forbidden_use_of_every_source_withholds_credit(self):
        for sl, (pre, m, _) in SOURCES.items():
            for ul, use in FORBIDDEN.items():
                self.check(f"{sl}: {ul}", pre + use.format(m=m), 0)

    def test_outside_reads_depend_on_the_source(self):
        for sl, (pre, m, cls) in SOURCES.items():
            for ul, use in OUTSIDE_READS.items():
                self.check(f"{sl}: {ul}", "import subprocess\n" + pre + use.format(m=m), 8 if cls == "attr" else 0)

    def test_allowed_uses_keep_credit_unless_getattr_reached_the_module(self):
        for sl, (pre, m, cls) in SOURCES.items():
            for ul, use in ALLOWED.items():
                self.check(f"{sl}: {ul}", pre + use.format(m=m), 0 if cls == "getattr" else 8)

    def test_the_forbidden_uses_in_the_tool_module_and_in_a_file_nobody_imports(self):
        for sl in ("an imported module", "getattr of a repo module", "an outside module's attribute"):
            pre, m, _ = SOURCES[sl]
            for ul, use in FORBIDDEN.items():
                self.check(f"{sl}: {ul}", pre + use.format(m=m), 0, place="agent.py")
                self.check(f"{sl}: {ul}", pre + use.format(m=m), 0, place="tools/other.py")

    def test_a_capitalised_outside_class_may_be_used_anywhere(self):
        for ul, use in CLASS_USES.items():
            self.check(f"class: {ul}", CLASS_PRELUDE + use, 8)
            self.check(f"class: {ul}", CLASS_PRELUDE + use, 8, place="agent.py")
        self.check("a store on a class", CLASS_PRELUDE + "Counter.x = 1\n", 0)

    def test_the_class_exception_stays_bounded(self):
        for label, (pre, m) in CLASS_NOT_EXEMPT.items():
            for ul in ("an argument to a repo function", "assigned", "a list", "returned"):
                self.check(f"{label}: {ul}", pre + FORBIDDEN[ul].format(m=m), 0)

    def test_the_reason_names_the_file_and_line(self):
        files = dict(TOOL, **{"patch.py": "import lib\n\n\nchange = print\nX = getattr(lib, 'subprocess')\n",
                              "kit_guard.py": HELPER})
        with Repo(files) as d:
            text = str([c for c in audit(d)["checks"] if c["id"] in ("G1", "G2", "G3")])
        self.assertIn("patch.py:5", text)


# ------------------------------------------------------------------ R7-02: every place the options can be bound
SDK = next(k for k in KINDS if k.name.startswith("PreToolUse"))
CALL = SDK.wire.split(" = ", 1)[1].strip()
PRE = "from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions\n"
CREDITED_PLACES = {
    "module level": "opts = {c}\nclient = ClaudeSDKClient(options=opts)\n",
    "module level, annotated": "opts: ClaudeAgentOptions = {c}\nclient = ClaudeSDKClient(options=opts)\n",
    "a function local": "def main():\n    opts = {c}\n    return ClaudeSDKClient(options=opts)\n",
    "a function local, annotated": "def main():\n    opts: ClaudeAgentOptions = {c}\n"
                                   "    return ClaudeSDKClient(options=opts)\n",
    "a method local": "class App:\n    def start(self):\n        opts = {c}\n"
                      "        return ClaudeSDKClient(options=opts)\n",
    "inline in the client": "client = ClaudeSDKClient(options={c})\n",
}
UNCREDITED_PLACES = {
    "a class body": "class Holder:\n    opts = {c}\nclient = ClaudeSDKClient(options=Holder.opts)\n",
    "a class body, annotated": "class Holder:\n    opts: ClaudeAgentOptions = {c}\n"
                               "client = ClaudeSDKClient(options=Holder.opts)\n",
    "a class body, nothing after": "class Holder:\n    opts = {c}\n",
    "a nested class body": "class Outer:\n    class Holder:\n        opts = {c}\n"
                           "client = ClaudeSDKClient(options=Outer.Holder.opts)\n",
    "a class body in a function": "def main():\n    class Holder:\n        opts = {c}\n"
                                  "    return ClaudeSDKClient(options=Holder.opts)\n",
    "an instance attribute": "class App:\n    def __init__(self):\n        self.opts = {c}\n",
    "a class attribute set from outside": "class Holder:\n    pass\nHolder.opts = {c}\n",
    "a default argument": "def start(o={c}):\n    return ClaudeSDKClient(options=o)\n",
    "a keyword-only default": "def start(*, o={c}):\n    return ClaudeSDKClient(options=o)\n",
    "a lambda default": "start = lambda o={c}: ClaudeSDKClient(options=o)\n",
    "a list": "ALL = [{c}]\nclient = ClaudeSDKClient(options=ALL[0])\n",
    "a tuple": "ALL = ({c},)\nclient = ClaudeSDKClient(options=ALL[0])\n",
    "a dict value": "ALL = {{'a': {c}}}\nclient = ClaudeSDKClient(options=ALL['a'])\n",
    "returned by a method": "class App:\n    def make(self):\n        return {c}\n"
                            "client = ClaudeSDKClient(options=App().make())\n",
    "returned by a static method": "class App:\n    @staticmethod\n    def make():\n        return {c}\n"
                                   "client = ClaudeSDKClient(options=App.make())\n",
    "returned by a class-body function": "class App:\n    def make():\n        return {c}\n",
}
CLASS_CHANGES = {
    "clear": "Holder.opts.hooks['PreToolUse'].clear()\n",
    "append": "Holder.opts.hooks['PreToolUse'].append(None)\n",
    "replace the dict": "Holder.opts.hooks = {}\n",
    "an instance read then clear": "Holder().opts.hooks['PreToolUse'].clear()\n",
    "getattr then clear": "getattr(Holder, 'opts').hooks['PreToolUse'].clear()\n",
}


class R7OptionsPlaces(unittest.TestCase):
    def check(self, label, wiring, want):
        with self.subTest(case=label):
            pts, st = score({"agent.py": SDK.source(module=PRE, wiring=wiring)})
            self.assertEqual(pts, want, (st, wiring))

    def test_module_level_and_function_locals_keep_credit(self):
        for label, w in CREDITED_PLACES.items():
            self.check(label, w.format(c=CALL), 8)

    def test_a_change_to_a_function_local_loses_credit(self):
        self.check("a local, cleared", "def main():\n    opts = {c}\n    opts.hooks['PreToolUse'].clear()\n"
                   "    return ClaudeSDKClient(options=opts)\n".format(c=CALL), 0)

    def test_every_other_binding_place_is_unresolved(self):
        for label, w in UNCREDITED_PLACES.items():
            self.check(label, w.format(c=CALL), 0)

    def test_class_held_options_then_a_change(self):
        for form in ("class Holder:\n    opts = {c}\n", "class Holder:\n    opts: ClaudeAgentOptions = {c}\n"):
            for label, change in CLASS_CHANGES.items():
                self.check(f"{form.splitlines()[1].strip()[:20]}: {label}",
                           form.format(c=CALL) + change + "client = ClaudeSDKClient(options=Holder.opts)\n", 0)


# ------------------------------------------------------------------ R7-03: each callable's own options, differential
SHELL_CALLABLES = ("subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
                   "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput", "os.popen",
                   "asyncio.create_subprocess_shell")
OPEN_CALLABLES = ("open", "io.open", "codecs.open")
# Candidate literal values for every written option, valid and not: the audit may credit only the harmless ones.
CANDIDATES = {
    "shell": ["True", "False", "1"], "capture_output": ["True", "False"], "text": ["True", "False", "'yes'"],
    "check": ["True", "False"], "universal_newlines": ["True", "False"],
    "timeout": ["5", "2.5", "None", "'5'", "True"],
    "encoding": ["'utf-8'", "'latin-1'", "'no-such-codec'", "None", "5"],
    "errors": ["'strict'", "'replace'", "'no-such-handler'", "None"], "cwd": ["'.'", "'sub'"],
    "mode": ["'r'", "'rb'", "'rt'", "'w'", "'wb'", "'a'", "'r+'", "'rw'", "'b'", "'U'", "'rbt'", "'x'"],
    "buffering": ["-1", "0", "1", "4096", "'1'", "None"],
    "newline": ["None", "''", "'\\n'", "'\\r\\n'", "'x'"],
}
EXTRA_OPTIONS = ("stdout", "stderr", "stdin", "input", "bufsize", "env", "executable", "close_fds")


def _invoke(full, kw, folder):
    """Call the real callable with the harmless operation (`true`, or a file in folder) and kw; raise as it raises."""
    if full.startswith("subprocess.") or full == "os.popen":
        fn = getattr(subprocess, full.split(".")[1]) if full != "os.popen" else os.popen
        if full == "subprocess.Popen":
            fn("true", **kw).wait()
        elif full == "os.popen":
            fn("true", **kw).close()
        else:
            fn("true", **kw)
        return
    if full == "asyncio.create_subprocess_shell":
        async def go():
            p = await asyncio.create_subprocess_shell("true", **kw)
            await p.wait()
        asyncio.run(go())
        return
    target = folder / "f.txt"
    mode = kw.get("mode", "r")
    if "x" in str(mode):
        target.unlink(missing_ok=True)
    else:
        target.write_text("a\n")
    fn = {"open": open, "io.open": __import__("io").open, "codecs.open": codecs.open}[full]
    fn(str(target), **kw).close()


class R7CallableOptions(unittest.TestCase):
    """Whatever the audit credits must not raise when really called (the written list matches the callable)."""

    @classmethod
    def setUpClass(cls):
        cls.a = load_audit("audit_r7_options")
        cls.folder = Path(tempfile.mkdtemp())
        (cls.folder / "sub").mkdir()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.folder)

    def credited(self, full, kw):
        cat = "shell" if full not in OPEN_CALLABLES else "open"
        call = ast.parse(f"{full}(P{''.join(', ' + k + '=' + v for k, v in kw.items())})", mode="eval").body
        return self.a._op_arg(call, cat, full) is not None

    def check(self, full, kw):
        if not self.credited(full, kw):
            return 0
        real = {k: ast.literal_eval(v) for k, v in kw.items()}
        cwd = os.getcwd()
        try:
            os.chdir(self.folder)
            with self.subTest(call=f"{full}({kw})"):
                try:
                    _invoke(full, real, self.folder)
                except Exception as e:                       # the audit credited an option that raises
                    self.fail(f"credited but raises {type(e).__name__}: {e}")
        finally:
            os.chdir(cwd)
        return 1

    def test_the_written_lists_are_each_callables_own(self):
        a = load_audit("audit_r7_lists")
        self.assertNotIn("check", a.ALLOWED_OPTIONS["subprocess.check_output"])
        self.assertNotIn("capture_output", a.ALLOWED_OPTIONS["subprocess.check_output"])
        for full in SHELL_CALLABLES + OPEN_CALLABLES:
            self.assertIn(full, a.ALLOWED_OPTIONS)

    def test_every_single_written_option_with_every_candidate_value(self):
        a = load_audit("audit_r7_single")
        for full in SHELL_CALLABLES + OPEN_CALLABLES:
            credited = 0
            for opt in set(a.ALLOWED_OPTIONS[full]) | set(EXTRA_OPTIONS) | {"check", "capture_output"}:
                for v in CANDIDATES.get(opt, ["None", "True", "1"]):
                    credited += self.check(full, {opt: v})
            with self.subTest(callable=full):
                self.assertGreater(credited, 0)

    def test_every_pair_of_written_options(self):
        a = load_audit("audit_r7_pairs")
        for full in SHELL_CALLABLES + OPEN_CALLABLES:
            opts = sorted(a.ALLOWED_OPTIONS[full])
            for o1, o2 in itertools.combinations(opts, 2):
                for v1 in CANDIDATES.get(o1, ["None"])[:4]:
                    for v2 in CANDIDATES.get(o2, ["None"])[:4]:
                        self.check(full, {o1: v1, o2: v2})

    def test_the_written_f2_text_matches_the_table(self):
        a = load_audit("audit_r7_text")
        text = dict(a.CANONICAL_FORMS)["F2 Tool refusal"]
        self.assertIn("check_output: shell, text, timeout", text)
        self.assertNotIn("for subprocess.run and check_output", text)


# ------------------------------------------------------------------ the brace boundary, generated
DESTRUCTIVE = ["git push", "git clean -fd", "git reset --hard", "rm -rf x", "rm -r x", "rm x --recursive",
               "git -c alias.p=x p", "git -C dir push", "sudo rm -rf x"]
BRACE_CONTROLS = ["echo {a,b}", "ls {src,tests}", "git {status,log}", "awk '{print $1}'",
                  "find . -name x -exec ls {} \\;", "echo {1..3}", "mkdir -p a/{b,c}", "git log --format={h,s}",
                  "rm {a,b}.txt", "echo '{\"a\": 1}'"]


def brace_forms(cmd):
    """Brace spellings of cmd: each word as one alternative of a group, a group inside a word, and two neighbouring
    words joined into one group (the shell makes them two words again)."""
    words = cmd.split()
    out = []
    for i, w in enumerate(words):
        def put(x):
            return " ".join(words[:i] + [x] + words[i + 1:])
        out += [put("{" + w + ",zz}"), put("{zz," + w + "}"), put("{" + w + ",{q,r}}")]
        if len(w) > 1:
            out.append(put(w[0] + "{" + w[1:] + ",zz}"))
            out.append(put(w[:-1] + "{" + w[-1] + ",z}"))
        if i + 1 < len(words):
            out.append(" ".join(words[:i] + ["{" + w + "," + words[i + 1] + "}"] + words[i + 2:]))
    return out


class R7Braces(unittest.TestCase):
    def test_every_destructive_member_in_every_brace_form_is_refused(self):
        kg = load_kit_guard()
        n = 0
        for cmd in DESTRUCTIVE:
            for form in brace_forms(cmd):
                for wrapped in (form, f"bash -c '{form}'", f"echo $({form})", f"true; {form}"):
                    n += 1
                    with self.subTest(value=wrapped):
                        self.assertTrue(kg.refuses(wrapped))
        self.assertGreater(n, 300)

    def test_argument_vectors_with_braces_are_refused(self):
        kg = load_kit_guard()
        for argv in (["git", "{push,status}"], ["r{m,x}", "-rf", "x"], ["sh", "-c", "git {push,log}"]):
            with self.subTest(argv=argv):
                self.assertTrue(kg.refuses(argv))

    def test_sequences_in_destructive_words(self):
        kg = load_kit_guard()
        for v in ("rm -{q..s}f x", "git pu{r..t}h", "{q..s}m -rf x"):
            with self.subTest(value=v):
                self.assertTrue(kg.refuses(v))

    def test_too_large_or_too_deep_is_refused(self):
        kg = load_kit_guard()
        big = "{" + ",".join(f"a{i}" for i in range(70)) + "}"
        for v in ("echo " + big, "echo {a,{b,{c,{d,{e,{f,g}}}}}}", "echo {a,b}{a,b}{a,b}{a,b}{a,b}",
                  "echo {a,b} {a,b} {a,b} {a,b} {a,b} {a,b} {a,b} {a,b} {a,b}"):
            with self.subTest(value=v[:60]):
                self.assertTrue(kg.refuses(v))

    def test_ordinary_braces_stay_allowed(self):
        kg = load_kit_guard()
        for v in BRACE_CONTROLS:
            with self.subTest(value=v):
                self.assertFalse(kg.refuses(v))


if __name__ == "__main__":
    unittest.main()
