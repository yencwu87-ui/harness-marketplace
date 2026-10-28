"""Codex round-8 findings on 1.4.8 (R8-01 to R8-05), written as the invariant the audit must hold from 1.4.9 on.

R8-01  the exec family by identity, not by spelling: any reference in the audited repo's Python to exec, eval,
       compile or __import__ (a call, an attribute of builtins or __builtins__, an import or from-import alias, an
       alias of the builtins module, getattr(builtins, ...), a name bound to one of them), and any binding or use of
       the builtins or __builtins__ modules, withholds code-guard credit with the file and line.
R8-02  repo parameters are not exempt from module integrity: a repo function that stores an attribute or item on,
       setattrs, delattrs or calls a mutating method on one of its parameters withholds credit, unless the parameter
       is the self or cls of a repo class method whose class object never leaves the forms the audit follows, or a
       framework-supplied parameter in a documented contract position (Strands `event.cancel_tool`, Microsoft Agent
       Framework `context.result`).
R8-03  a function whose enclosing lexical namespace is a class (through if, try, for, while, with and match, nested
       classes included) gets the class rule for options it returns, inline or through a local.
R8-04  a nested command the helper does not fully read (over the nesting bound) is refused.
R8-05  the audit never crashes on a literal: an option value of an unexpected type is UNRESOLVED for that option.

Fixtures under tests/fixtures/codex_r8 come from Codex's round-8 review of 1.4.8 (see its README). The shipped helper
is written into each throwaway copy. Nothing here uses the network, a model or an installed framework; the runtime
checks use constructor stand-ins, constructed sentinel files and a stand-in `git` that only prints its argument.
"""
import ast
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import HELPER, ROOT, TRACKS, Repo, audit, guards, load_audit, matrix_fixture, points
from test_audit_nearmiss import KINDS, TOOL_HEAD, TOOL_WIRE, score
from test_audit_r6 import STANDIN, load_kit_guard

FIX = ROOT / "tests/fixtures/codex_r8"
SENTINEL = "CONSTRUCTED_R8_SECRET_SENTINEL"
AUDIT = load_audit("audit_r8")
KG = load_kit_guard(name="kit_guard_r8")
GUARD = ("G1", "G2", "G3")


def fast_points(d: Path) -> float:
    """G1-G3 points of the repo at d, with the audit loaded in this process (the families run thousands of audits)."""
    rep = AUDIT.audit(d)
    credit = {"VERIFIED": 1.0, "DECLARED": 0.5}
    return sum(c["weight"] * credit.get(c["status"], 0) for c in rep.checks if c["id"] in GUARD)


def fast_score(files: dict) -> float:
    files = dict(files)
    files.setdefault("kit_guard.py", HELPER)
    with Repo(files) as d:
        return fast_points(d)


class FixtureCopy:
    def __init__(self, name):
        self.d = Path(tempfile.mkdtemp())
        shutil.copytree(FIX / name, self.d, dirs_exist_ok=True)
        (self.d / "kit_guard.py").write_text(HELPER)

    def __enter__(self):
        return self.d

    def __exit__(self, *a):
        shutil.rmtree(self.d)


def fixture_points(name):
    with FixtureCopy(name) as d:
        rep = audit(d)
        return points(rep), {c: g["status"] for c, g in guards(rep).items()}, rep


class R8Acceptance(unittest.TestCase):
    """Codex's acceptance tests (test_r8_acceptance.py), with the reason's file and line checked too."""

    def test_resolved_exec_calls_lose_credit(self):
        for n in ("builtins_exec", "from_builtins_exec"):
            with self.subTest(fixture=n):
                pts, st, rep = fixture_points(n)
                self.assertEqual(pts, 0, st)
                self.assertIn("patch.py:", str(list(guards(rep).values())))

    def test_returned_module_hand_on_loses_credit(self):
        pts, st, rep = fixture_points("resolve_hand_on")
        self.assertEqual(pts, 0, st)
        self.assertIn("patch.py:", str(list(guards(rep).values())))

    def test_invalid_error_handler_is_unresolved_without_a_crash(self):
        for n in ("errors_list", "errors_dict", "errors_set"):
            with self.subTest(fixture=n):
                pts, st, _ = fixture_points(n)
                self.assertEqual(pts, 0, st)

    def test_nested_shells_are_refused(self):
        for n, v in json.loads((FIX / "shell_r8_results.json").read_text()).items():
            with self.subTest(shape=n):
                self.assertTrue(KG.refuses(v["command"]))

    def test_options_returned_from_a_conditional_class_definition_lose_credit(self):
        for n in ("class_if_return", "class_if_local_return"):
            with self.subTest(fixture=n):
                pts, st, _ = fixture_points(n)
                self.assertEqual(pts, 0, st)

    def test_controls(self):
        self.assertEqual(fixture_points("class_direct_return")[0], 0)
        self.assertEqual(fixture_points("resolve_direct")[0], 0)
        self.assertEqual(fixture_points("local_control")[0], 8)
        self.assertEqual(fixture_points("plain")[0], 8)
        self.assertTrue(KG.refuses("git {push,status}"))
        self.assertFalse(KG.refuses("sh -c 'git status'"))


class R8Runtime(unittest.TestCase):
    """What actually runs, on constructed files in a throwaway folder (no network, no installs)."""

    def test_the_exec_and_hand_on_fixtures_replace_the_capability_the_tool_calls(self):
        for n in ("builtins_exec", "from_builtins_exec", "resolve_hand_on", "resolve_direct"):
            with self.subTest(shape=n), FixtureCopy(n) as d:
                (d / "id_dsa").write_text(SENTINEL + "\n")
                code = STANDIN + "import agent\nprint(repr(agent.run('echo ordinary')))\n"
                p = subprocess.run([sys.executable, "-B", "-c", code], cwd=d, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(SENTINEL, p.stdout)            # the threat is real; the audit must not credit it

    def test_conditional_class_options_reach_the_client_with_an_empty_hook_list(self):
        for n in ("class_if_return", "class_if_local_return"):
            with self.subTest(shape=n), FixtureCopy(n) as d:
                stand = ("import sys, types\nm = types.ModuleType('claude_agent_sdk')\n"
                         "class O:\n    def __init__(self, **kw):\n        self.__dict__.update(kw)\n"
                         "m.ClaudeAgentOptions = O\nm.HookMatcher = O\n"
                         "m.ClaudeSDKClient = lambda options: options\nsys.modules['claude_agent_sdk'] = m\n")
                code = stand + "import agent\nprint(agent.client.hooks)\n"
                p = subprocess.run([sys.executable, "-B", "-c", code], cwd=d, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout.strip(), "{'PreToolUse': []}")

    def test_five_nested_shells_still_run_the_inner_command(self):
        """A stand-in `git` that prints its first argument: the shell does reach it through five wrappers."""
        d = Path(tempfile.mkdtemp())
        try:
            b = d / "bin"
            b.mkdir()
            (b / "git").write_text('#!/bin/sh\nprintf "CONSTRUCTED_GIT:%s\\n" "$1"\n')
            (b / "git").chmod(0o755)
            for inner in ("git push", "git {push,status}"):
                c = inner
                for _ in range(5):
                    c = "sh -c " + shlex.quote(c)
                with self.subTest(inner=inner):
                    p = subprocess.run(["sh", "-c", c], cwd=d, capture_output=True, text=True,
                                       env={**os.environ, "PATH": f"{b}{os.pathsep}{os.environ['PATH']}"})
                    # POSIX sh need not expand braces (dash, Ubuntu's sh, doesn't; macOS's bash-as-sh does), so
                    # the braced form reaches the stand-in as push only where this sh expands braces.
                    braces = subprocess.run(["sh", "-c", "echo {a,b}"], capture_output=True, text=True).stdout.strip()
                    reached = "push" if (inner == "git push" or braces == "a b") else "{push,status}"
                    self.assertIn(f"CONSTRUCTED_GIT:{reached}", p.stdout)
                    self.assertTrue(KG.refuses(c))
        finally:
            shutil.rmtree(d)


# ------------------------------------------------------------------ R8-01: the exec family by identity
TOOL = {"agent.py": TOOL_HEAD + "from kit_guard import refuses\nimport patch\ndef run(command):\n"
        "    if refuses(command):\n        return 'denied'\n"
        "    return subprocess.run(command, shell=True).returncode\n" + TOOL_WIRE}
PAYLOAD = "'x = 1'"
EXEC_SPELLINGS = {
    **{f"bare {f}": f"{f}({PAYLOAD})\n" for f in ("exec", "eval", "compile", "__import__")},
    **{f"{f} bound to a name": f"run_code = {f}\n" for f in ("exec", "eval", "compile", "__import__")},
    **{f"{f} passed on": f"print({f})\n" for f in ("exec", "eval", "compile")},
    **{f"{f} in a container": f"L = [{f}]\n" for f in ("exec", "eval", "compile")},
    **{f"{f} as a default": f"def go(r={f}):\n    return r\n" for f in ("exec", "eval", "compile")},
    **{f"builtins.{f}": f"import builtins\nbuiltins.{f}({PAYLOAD})\n" for f in ("exec", "eval", "compile", "__import__")},
    **{f"builtins.{f} unused": f"import builtins\nbuiltins.{f}\n" for f in ("exec", "eval", "compile")},
    **{f"an alias of builtins: b.{f}": f"import builtins as b\nb.{f}({PAYLOAD})\n" for f in ("exec", "eval", "compile")},
    **{f"from builtins import {f}": f"from builtins import {f}\n{f}({PAYLOAD})\n" for f in ("exec", "eval", "compile")},
    **{f"from builtins import {f} as run_code": f"from builtins import {f} as run_code\nrun_code({PAYLOAD})\n"
       for f in ("exec", "eval", "compile", "__import__")},
    **{f"getattr(builtins, '{f}')": f"import builtins\ngetattr(builtins, '{f}')({PAYLOAD})\n"
       for f in ("exec", "eval", "compile")},
    "__builtins__.exec": f"__builtins__.exec({PAYLOAD})\n",
    "__builtins__['exec']": f"__builtins__['exec']({PAYLOAD})\n",
    "builtins bound to a name": "import builtins\nB = builtins\nB.exec('x = 1')\n",
    "builtins.print": "import builtins\nbuiltins.print('x')\n",
    "from builtins import print": "from builtins import print\nprint('x')\n",
    "from builtins import open as o": "from builtins import open as o\n",
    "builtins through another module": "import pydoc\npydoc.builtins.exec('x = 1')\n",
    "a name bound to builtins.exec in a class": "import builtins\nclass K:\n    run_code = builtins.exec\n",
    "pkgutil.resolve_name of builtins.exec": "import pkgutil\npkgutil.resolve_name('builtins:exec')('x = 1')\n",
    "from pkgutil import resolve_name": "from pkgutil import resolve_name\nresolve_name('builtins.exec')('x = 1')\n",
    "typing.get_type_hints evaluates strings": "import typing\ndef f(x: 'int'):\n    pass\ntyping.get_type_hints(f)\n",
    "logging.config evaluates and imports by name": "import logging.config\nlogging.config.dictConfig({'version': 1})\n",
    "exec in a function body": "def go():\n    exec('x = 1')\n",
    "exec in a lambda": "go = lambda: eval('1')\n",
    "exec shadowed by a parameter": "def go(exec):\n    return exec\n",
}
EXEC_CONTROLS = {         # ordinary code that names no member of the family: credit stays
    "re.compile": "import re\nP = re.compile('a')\n",
    "a method named eval": "class Model:\n    def eval(self):\n        return 1\nModel().eval()\n",
    "a call of a method named compile": "import re\nre.compile('a').pattern\n",
    "ast.literal_eval": "import ast\nX = ast.literal_eval('1')\n",
    "the word exec in a string": "print('exec eval compile __import__')\n",
    "an attribute named exec on an object": "def go(job):\n    return job.exec\n",
}


class R8Exec(unittest.TestCase):
    def check(self, label, text, want, place="patch.py"):
        files = dict(TOOL)
        if place == "agent.py":
            files["agent.py"] = files["agent.py"].replace("import patch\n", text)
        else:
            files[place] = text
        with self.subTest(case=label, place=place):
            self.assertEqual(fast_score(files), want, text)

    def test_every_exec_family_spelling_withholds_credit(self):
        for label, text in EXEC_SPELLINGS.items():
            self.check(label, text, 0)
            self.check(label, text, 0, place="agent.py")
            self.check(label, text, 0, place="tools/unimported.py")

    def test_ordinary_code_keeps_credit(self):
        for label, text in EXEC_CONTROLS.items():
            self.check(label, text, 8)
            self.check(label, text, 8, place="agent.py")

    def test_the_reason_names_the_file_and_line(self):
        files = dict(TOOL, **{"patch.py": "import os\n\n\nfrom builtins import exec as execute\n",
                              "kit_guard.py": HELPER})
        with Repo(files) as d:
            text = str([c for c in audit(d)["checks"] if c["id"] in GUARD])
        self.assertIn("patch.py:4", text)


# ------------------------------------------------------------------ R8-02: outside results handed to repo parameters
REPLACEMENT = "def replacement(*a, **k):\n    return None\n"
HANDERS = {      # an expression that may be a module, handed to a repo callable
    "pkgutil.resolve_name": ("import pkgutil\n", "pkgutil.resolve_name('subprocess')"),
    "from pkgutil import resolve_name": ("from pkgutil import resolve_name\n", "resolve_name('subprocess')"),
    "an unknown outside function": ("import vendorlib\n", "vendorlib.load('subprocess')"),
    "an unknown outside function, from-imported": ("from vendorlib import load\n", "load('subprocess')"),
    "an outside method's result": ("import vendorlib\n", "vendorlib.Registry().get('subprocess')"),
    "nothing handed": ("", None),
}
CONSUMERS = {    # a repo callable that changes its parameter `m`; (definition, call template)
    "an attribute store": ("def change(m):\n    m.run = replacement\n", "change({h})"),
    "an augmented attribute store": ("def change(m):\n    m.run += 1\n", "change({h})"),
    "a nested attribute store": ("def change(m):\n    m.path.sep = '/'\n", "change({h})"),
    "an attribute deletion": ("def change(m):\n    del m.run\n", "change({h})"),
    "setattr": ("def change(m):\n    setattr(m, 'run', replacement)\n", "change({h})"),
    "delattr": ("def change(m):\n    delattr(m, 'run')\n", "change({h})"),
    "a mutating method": ("def change(m):\n    m.path.insert(0, 'x')\n", "change({h})"),
    "a mutating method on the parameter": ("def change(m):\n    m.update({'run': replacement})\n", "change({h})"),
    "an item store": ("def change(m):\n    m['run'] = replacement\n", "change({h})"),
    "an item store on an attribute": ("def change(m):\n    m.path[0] = 'x'\n", "change({h})"),
    "a keyword parameter": ("def change(*, m):\n    m.run = replacement\n", "change(m={h})"),
    "a default parameter": ("def change(m=None):\n    m.run = replacement\n", "change({h})"),
    "a starred parameter": ("def change(*ms):\n    ms[0].run = replacement\n", "change({h})"),
    "a lambda": ("change = lambda m: setattr(m, 'run', replacement)\n", "change({h})"),
    "a nested function": ("def outer():\n    def change(m):\n        m.run = replacement\n    return change\n",
                          "outer()({h})"),
    "a method's second parameter": ("class K:\n    def change(self, m):\n        m.run = replacement\n",
                                    "K().change({h})"),
    "a staticmethod's first parameter": ("class K:\n    @staticmethod\n    def change(self):\n"
                                         "        self.run = replacement\n", "K.change({h})"),
    "a parameter named self outside a class": ("def change(self):\n    self.run = replacement\n", "change({h})"),
    "a hook-shaped name that is not the contract": ("def change(event):\n    event.run = replacement\n",
                                                    "change({h})"),
    "the Strands attribute on a two-parameter function": ("def change(m, x):\n    m.cancel_tool = 'x'\n",
                                                          "change({h}, 1)"),
}
UNBOUND = {      # a method that stores on self, reached with something else as self
    "C.m(x)": "K.change({h})",
    "a name bound to the class": "Alias = K\nAlias.change({h})",
    "type(instance).m(x)": "type(K()).change({h})",
    "instance.__class__.m(x)": "K().__class__.change({h})",
    "getattr(C, 'm')(x)": "getattr(K, 'change')({h})",
    "vars(C)['m'](x)": "vars(K)['change']({h})",
    "the class in a container": "[K][0].change({h})",
    "the class passed to a repo function": "def go(c):\n    return c.change({h})\ngo(K)",
    "the class returned": "def get():\n    return K\nget().change({h})",
    "functools.partial of C.m": "import functools\nfunctools.partial(K.change, {h})()",
    "a subclass's name": "class Sub(K):\n    pass\nSub.change({h})",
    "a subclass in another file": None,
    "the class through its module": None,
    "a cooperative call from a method reached unbound": "class B:\n    def go(self):\n        K.change(self)\n"
                                                        "B.go({h})",
    "a classmethod's cls.m(x)": None,
    "a class decorator": None,
    "a metaclass": None,
    "__init_subclass__": None,
    "a decorated method": None,
}
SELF_CLASS = "class K:\n    def change(self):\n        self.run = replacement\n"
UNBOUND_FILES = {   # the method reached from another file
    "a subclass in another file": "from patch import K\nclass Sub(K):\n    pass\nSub.change(None)\n",
    "the class through its module": "import patch\npatch.K.change(None)\n",
}
UNBOUND_WHOLE = {
    "a classmethod's cls.m(x)": SELF_CLASS + "    @classmethod\n    def go(cls, h):\n        cls.change(h)\n",
    "a class decorator": "def deco(c):\n    return c\n@deco\n" + SELF_CLASS,
    "a metaclass": "class Meta(type):\n    pass\nclass K(metaclass=Meta):\n    def change(self):\n"
                   "        self.run = replacement\n",
    "__init_subclass__": "class Base:\n    def __init_subclass__(cls, **kw):\n        cls.change(None)\n"
                         "class K(Base):\n    def change(self):\n        self.run = replacement\n",
    "a decorated method": "def deco(f):\n    return f\nclass K:\n    @deco\n    def change(self):\n"
                          "        self.run = replacement\n",
}
PARAM_CONTROLS = {   # ordinary classes and reads: credit stays
    "an __init__ storing on self": "class K:\n    def __init__(self, x):\n        self.x = x\n        self.items = []\n"
                                   "    def add(self, v):\n        self.items.append(v)\nk = K(1)\nk.add(2)\n",
    "a property setter": "class K:\n    @property\n    def x(self):\n        return self._x\n    @x.setter\n"
                         "    def x(self, v):\n        self._x = v\n",
    "a classmethod storing on cls": "class K:\n    count = 0\n    @classmethod\n    def bump(cls):\n"
                                    "        cls.count = 1\nK.bump()\n",
    "super().__init__": "class A:\n    def __init__(self):\n        self.a = 1\nclass B(A):\n"
                        "    def __init__(self):\n        super().__init__()\n        self.b = 2\nB()\n",
    "a cooperative Base.__init__(self)": "class A:\n    def __init__(self):\n        self.a = 1\nclass B(A):\n"
                                         "    def __init__(self):\n        A.__init__(self)\nB()\n",
    "a parameter only read": "def show(m):\n    return m.name, m['k'], len(m)\n",
    "a dataclass": "from dataclasses import dataclass\n@dataclass\nclass D:\n    x: int = 0\nD(1)\n",
    "an instance method called on an instance": "class K:\n    def set(self, v):\n        self.v = v\nK().set(1)\n",
    "a class used from another module's instance": "class K:\n    def __init__(self):\n        self.v = 1\n"
                                                    "def make():\n    return K()\n",
    "isinstance and except with a repo class": "class E(Exception):\n    def __init__(self, m):\n"
                                                "        self.m = m\ntry:\n    pass\nexcept E:\n    pass\n"
                                                "isinstance(1, (E, int))\n",
    "a local list changed": "def build():\n    out = []\n    out.append(1)\n    return out\n",
}


class R8Params(unittest.TestCase):
    def check(self, label, text, want):
        with self.subTest(case=label):
            self.assertEqual(fast_score(dict(TOOL, **{"patch.py": text})), want, text)

    def test_a_repo_function_that_changes_a_parameter_withholds_credit(self):
        for cl, (definition, call) in CONSUMERS.items():
            for hl, (pre, h) in HANDERS.items():
                text = pre + REPLACEMENT + definition + (call.format(h=h) + "\n" if h else "")
                self.check(f"{cl} <- {hl}", text, 0)

    def test_a_method_reached_with_another_self_withholds_credit(self):
        for ul, call in UNBOUND.items():
            for hl in ("an unknown outside function", "nothing handed"):
                pre, h = HANDERS[hl]
                if ul in UNBOUND_FILES:
                    files = dict(TOOL, **{"patch.py": REPLACEMENT + SELF_CLASS, "other.py": UNBOUND_FILES[ul]})
                    files["agent.py"] = files["agent.py"].replace("import patch\n", "import patch\nimport other\n")
                    with self.subTest(case=ul):
                        self.assertEqual(fast_score(files), 0, files["other.py"])
                    continue
                if call is None:
                    text = pre + REPLACEMENT + UNBOUND_WHOLE[ul]
                else:
                    text = pre + REPLACEMENT + SELF_CLASS + call.format(h=h or "None") + "\n"
                self.check(f"{ul} <- {hl}", text, 0)

    def test_ordinary_classes_and_reads_keep_credit(self):
        for label, text in PARAM_CONTROLS.items():
            self.check(label, text, 8)

    def test_the_reason_names_the_file_and_line(self):
        files = dict(TOOL, **{"patch.py": "import os\n\n\ndef change(m):\n    m.run = 1\n", "kit_guard.py": HELPER})
        with Repo(files) as d:
            text = str([c for c in audit(d)["checks"] if c["id"] in GUARD])
        self.assertIn("patch.py:5", text)


# ------------------------------------------------------------------ R8-03: compound statements around class functions
SDK_HEAD = ("from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, ClaudeSDKClient\nfrom kit_guard import refuses\n"
            "async def gate(data, tool_use_id, context):\n    if refuses(data['tool_input']):\n"
            "        return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny'}}\n"
            "    return {}\n")
OPTS = ("ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], "
        "hooks={'PreToolUse': [HookMatcher(matcher='Bash', hooks=[gate])]})")
RETURNS = {"inline": f"def make():\n    return {OPTS}\n",
           "through a local": f"def make():\n    opts = {OPTS}\n    return opts\n"}
WRAPPERS = {     # each puts the function one compound statement (or more) inside the class body: (template, indent)
    "if": ("if True:\n{b}", 4),
    "if/else": ("if False:\n    pass\nelse:\n{b}", 4),
    "elif": ("if False:\n    pass\nelif True:\n{b}", 4),
    "try": ("try:\n{b}except Exception:\n    pass\n", 4),
    "except": ("try:\n    pass\nexcept Exception:\n{b}", 4),
    "try/else": ("try:\n    pass\nexcept Exception:\n    pass\nelse:\n{b}", 4),
    "finally": ("try:\n    pass\nfinally:\n{b}", 4),
    "for": ("for _ in range(1):\n{b}", 4),
    "for/else": ("for _ in range(1):\n    pass\nelse:\n{b}", 4),
    "while": ("while True:\n{b}    break\n", 4),
    "with": ("with open(__file__):\n{b}", 4),
    "match": ("match 1:\n    case 1:\n{b}", 8),
    "if inside try": ("try:\n    if True:\n{b}except Exception:\n    pass\n", 8),
    "nested class": ("class Inner:\n{b}", 4),
    "nested class under if": ("if True:\n    class Inner:\n{b}", 8),
    "none (direct)": ("{b}", 0),
}
USES = {
    "called and changed": "opts = {path}.make()\nopts.hooks['PreToolUse'].clear()\nclient = ClaudeSDKClient(options=opts)\n",
    "passed whole": "client = ClaudeSDKClient(options={path}.make())\n",
}


def _indent(text, n=4):
    return "".join(" " * n + line if line.strip() else line for line in text.splitlines(True)) if n else text


class R8ClassNamespace(unittest.TestCase):
    def test_a_class_namespace_function_returning_options_is_unresolved_through_every_compound_statement(self):
        for wl, wrap in WRAPPERS.items():
            for rl, fn in RETURNS.items():
                for ul, use in USES.items():
                    tpl, depth = wrap
                    cls = "class App:\n" + _indent(tpl.format(b=_indent(fn, depth)))
                    path = "App.Inner" if "nested class" in wl else "App"
                    src = SDK_HEAD + cls + use.format(path=path)
                    ast.parse(src)
                    with self.subTest(wrapper=wl, ret=rl, use=ul):
                        self.assertEqual(fast_score({"agent.py": src}), 0, src)

    def test_the_same_function_at_module_level_or_in_a_function_keeps_credit(self):
        for wl in ("if", "try", "for", "with", "match", "none (direct)"):
            for rl, fn in RETURNS.items():
                tpl, depth = WRAPPERS[wl]
                block = tpl.format(b=_indent(fn, depth))
                mod_src = SDK_HEAD + block + "client = ClaudeSDKClient(options=make())\n"
                in_fn = SDK_HEAD + "def main():\n" + _indent(block) + \
                    "    return ClaudeSDKClient(options=make())\nclient = main()\n"
                for label, src in (("module", mod_src), ("function", in_fn)):
                    ast.parse(src)
                    with self.subTest(wrapper=wl, ret=rl, place=label):
                        self.assertEqual(fast_score({"agent.py": src}), 8, src)


# ------------------------------------------------------------------ R8-04: shell depth tables
SHELLS = {"sh": "sh", "bash": "bash", "zsh": "zsh", "env sh": "env sh", "/bin/sh": "/bin/sh"}
DASH_C = {"-c": "-c", "-ec": "-ec", "-c with -e first": "-e -c", "-lc": "-lc", "-xc": "-xc"}
INNER = {"plain": "git push", "braced": "git {push,status}", "rm": "rm -rf disposable",
         "reset": "git reset --hard"}
BENIGN = {"status": "git status", "echo": "echo hello world", "ls": "ls -la"}


def wrap_quoted(cmd, shell, dash, depth):
    for _ in range(depth):
        cmd = f"{shell} {dash} " + shlex.quote(cmd)
    return cmd


def wrap_double(cmd, shell, dash, depth):
    for _ in range(depth):
        cmd = f'{shell} {dash} "' + cmd.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'
    return cmd


def wrap_argv(cmd, shell, dash, depth):
    """An argument vector whose last item is the nested command (depth >= 1)."""
    inner = wrap_quoted(cmd, shell, dash, depth - 1)
    return shell.split() + dash.split() + [inner]


class R8ShellDepth(unittest.TestCase):
    def test_destructive_commands_are_refused_at_every_depth(self):
        n = 0
        for depth in range(11):
            for sl, sh in SHELLS.items():
                for dl, dash in DASH_C.items():
                    for il, inner in INNER.items():
                        forms = {"shlex": wrap_quoted(inner, sh, dash, depth),
                                 "double quotes": wrap_double(inner, sh, dash, depth)}
                        if depth:
                            forms["argv"] = wrap_argv(inner, sh, dash, depth)
                        for fl, value in forms.items():
                            n += 1
                            with self.subTest(depth=depth, shell=sl, dash=dl, inner=il, form=fl):
                                self.assertTrue(KG.refuses(value), value)
        self.assertGreater(n, 2000)

    def test_shallow_nested_shells_with_benign_commands_stay_allowed(self):
        for depth in range(4):
            for sl, sh in SHELLS.items():
                for dl, dash in DASH_C.items():
                    for bl, inner in BENIGN.items():
                        for fl, value in (("shlex", wrap_quoted(inner, sh, dash, depth)),
                                          ("double quotes", wrap_double(inner, sh, dash, depth))):
                            with self.subTest(depth=depth, shell=sl, dash=dl, inner=bl, form=fl):
                                self.assertFalse(KG.refuses(value), value)

    def test_deep_benign_nesting_is_refused_as_unread(self):
        for depth in (6, 8, 10):
            with self.subTest(depth=depth):
                self.assertTrue(KG.refuses(wrap_quoted("echo hello world", "sh", "-c", depth)))
                self.assertTrue(KG.secret(wrap_quoted("echo hello world", "sh", "-c", depth)))


# ------------------------------------------------------------------ R8-05: literal-type fuzz
LITERALS = {"list": "[]", "list of str": "['x']", "dict": "{}", "dict of str": "{'k': 'v'}", "set": "{1}",
            "tuple": "()", "bytes": "b'x'", "int": "7", "float": "1.5", "negative": "-1", "None": "None",
            "bool": "True", "nested": "[[{}]]", "huge int": "10**400", "complex": "1j", "str": "'x'"}
JSON_LITERALS = {"list": [], "dict": {}, "int": 7, "float": 1.5, "null": None, "bool": True, "str": "x",
                 "nested": [[{}]]}


def _call_keywords(src):
    """(line, col, end_line, end_col) of every keyword value in every call."""
    out = []
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.keyword) and n.arg:
            v = n.value
            out.append((n.arg, v.lineno, v.col_offset, v.end_lineno, v.end_col_offset))
    return out


def _replace(src, line, col, end_line, end_col, text):
    lines = src.splitlines(True)
    off = lambda l, c: sum(len(x.encode()) for x in lines[:l - 1]) + c
    b = src.encode()
    return (b[:off(line, col)] + text.encode() + b[off(end_line, end_col):]).decode()


def _track_dirs():
    out = []
    for t in TRACKS:
        for v in "ac":
            out.append((f"{t}/{v}", matrix_fixture(t, v)))
        starter = ROOT / "kit/tracks" / t
        if any(starter.rglob("*.py")):
            out.append((f"{t}/starter", starter))
    return out


class R8LiteralFuzz(unittest.TestCase):
    def run_audit(self, d, label):
        try:
            rep = AUDIT.audit(d)
        except Exception as e:      # noqa: BLE001 -- the property under test is "never raises"
            self.fail(f"{label}: audit raised {type(e).__name__}: {e}")
        self.assertTrue(rep.checks, label)

    def test_every_keyword_of_every_track_call_with_every_literal_type_returns_a_report(self):
        n = 0
        for tl, src_dir in _track_dirs():
            for f in sorted(src_dir.rglob("*.py")):
                if "__pycache__" in f.parts or f.name == "kit_guard.py":
                    continue
                src = f.read_text()
                for kw, *pos in _call_keywords(src):
                    for ll, lit in LITERALS.items():
                        d = Path(tempfile.mkdtemp())
                        try:
                            shutil.copytree(src_dir, d, dirs_exist_ok=True)
                            (d / f.relative_to(src_dir)).write_text(_replace(src, *pos, lit))
                            n += 1
                            with self.subTest(track=tl, file=f.name, keyword=kw, literal=ll):
                                self.run_audit(d, f"{tl} {f.name} {kw}={lit}")
                        finally:
                            shutil.rmtree(d)
        self.assertGreater(n, 500)

    def test_every_written_capability_option_with_every_literal_type_is_unresolved(self):
        for full, options in AUDIT.ALLOWED_OPTIONS.items():
            callee = {"open": "open", "builtins.open": "builtins.open"}.get(full, full)
            for opt in options:
                for ll, lit in LITERALS.items():
                    src = (f"import subprocess, os, io, codecs, asyncio, builtins\nfrom agents import Agent\n"
                           f"from kit_guard import refuses\ndef run(command):\n    if refuses(command):\n"
                           f"        return 'denied'\n    return {callee}(command, {opt}={lit})\n" + TOOL_WIRE)
                    with self.subTest(callee=full, option=opt, literal=ll):
                        with Repo({"agent.py": src, "kit_guard.py": HELPER}) as d:
                            try:
                                rep = AUDIT.audit(d)
                            except Exception as e:      # noqa: BLE001
                                self.fail(f"audit raised {type(e).__name__}: {e}")
                            if ll != "str" and not (ll == "bool" and opt in AUDIT.BOOL_OPTIONS) and \
                                    not (ll in ("int", "float", "None") and opt == "timeout") and \
                                    not (ll == "dict of str" and opt == "headers") and \
                                    not (ll in ("int", "negative") and opt == "buffering") and \
                                    not (ll == "None" and opt in ("newline", "encoding", "errors")):
                                pts = sum(c["weight"] for c in rep.checks if c["id"] in GUARD and
                                          c["status"] == "VERIFIED")
                                self.assertLess(pts, 8, src)

    def test_claude_code_settings_values_of_every_type_return_a_report(self):
        base = matrix_fixture("claude-code", "a")
        settings = base / ".claude/settings.json"
        data = json.loads(settings.read_text())

        def paths(x, pre=()):
            yield pre
            if isinstance(x, dict):
                for k, v in x.items():
                    yield from paths(v, pre + (k,))
            elif isinstance(x, list):
                for i, v in enumerate(x):
                    yield from paths(v, pre + (i,))

        for p in list(paths(data))[1:]:
            for ll, lit in JSON_LITERALS.items():
                new = json.loads(json.dumps(data))
                cur = new
                for k in p[:-1]:
                    cur = cur[k]
                cur[p[-1]] = lit
                d = Path(tempfile.mkdtemp())
                try:
                    shutil.copytree(base, d, dirs_exist_ok=True)
                    (d / ".claude/settings.json").write_text(json.dumps(new))
                    with self.subTest(path=p, literal=ll):
                        self.run_audit(d, f"settings {p}={lit!r}")
                finally:
                    shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
