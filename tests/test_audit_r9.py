"""Codex round-9 findings on 1.4.9 (R9-01 to R9-04), written as the class each one belongs to, not as the instance.

R9-01  a binding of a self attribute in a class body is a binding wherever it sits in the class's lexical namespace
       (through if, try, for, while, with and match, at any depth), and in any binding form.
R9-02  an alias analysis bound fails closed: past it, the mutation target counts as held by the parameter.
R9-03  `__init_subclass__` of a repo base is found in the base's whole lexical namespace, in any binding form.
R9-04  the helper reads every POSIX blank and separator as one; any other control character, or a non-ASCII space,
       in a value it inspects makes the value refused.

The classes: R8-03, R9-01 and R9-03 are one mistake (a rule read the direct parent or the direct body instead of the
enclosing lexical namespace); R8-04 and R9-02 are one mistake (a bound failed open). So besides Codex's fixtures this
file generates (every rule that reads a namespace or its bindings) x (every compound wrapper, nested 1 to 3 deep),
the alias forms of R8-02, and the helper's whitespace table. The bounds table has its own tests in test_bounds.py.

Fixtures under tests/fixtures/codex_r9 come from Codex's round-9 review of 1.4.9 (see its README). Nothing here uses
the network, a model or an installed framework; the runtime checks use constructor stand-ins, constructed sentinel
files and a stand-in `git` that only prints its arguments.
"""
import ast
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import HELPER, ROOT, Repo, audit, guards, load_audit, points
from test_audit_r6 import load_kit_guard

FIX = ROOT / "tests/fixtures/codex_r9"
SENTINEL = "CONSTRUCTED_R9_SECRET_SENTINEL"
AUDIT = load_audit("audit_r9")
KG = load_kit_guard(name="kit_guard_r9")
GUARD = ("G1", "G2", "G3")


def fast_points(d: Path) -> float:
    rep = AUDIT.audit(d)
    credit = {"VERIFIED": 1.0, "DECLARED": 0.5}
    return sum(c["weight"] * credit.get(c["status"], 0) for c in rep.checks if c["id"] in GUARD)


def fast_score(files: dict) -> float:
    files = dict(files)
    files.setdefault("kit_guard.py", HELPER)
    with Repo(files) as d:
        return fast_points(d)


class FixtureCopy:
    """A throwaway copy of one round-9 fixture with the shipped helper, the sentinel and an ordinary file beside it."""

    def __init__(self, name):
        self.d = Path(tempfile.mkdtemp())
        shutil.copytree(FIX / name, self.d, dirs_exist_ok=True)
        (self.d / "kit_guard.py").write_text(HELPER)
        (self.d / "id_dsa").write_text(SENTINEL)
        (self.d / "ordinary").write_text("ordinary")

    def __enter__(self):
        return self.d

    def __exit__(self, *a):
        shutil.rmtree(self.d)


def fixture_points(name):
    with FixtureCopy(name) as d:
        return fast_points(d)


def fixture_reasons(name):
    with FixtureCopy(name) as d:
        return " ".join(str(c) for c in audit(d)["checks"] if c["id"] in GUARD)


def stand_in_git(d: Path) -> dict:
    b = d / "bin"
    b.mkdir(exist_ok=True)
    (b / "git").write_text('#!/bin/sh\nprintf "CONSTRUCTED_GIT:%s\\n" "$*"\n')
    (b / "git").chmod(0o755)
    return {**os.environ, "PATH": f"{b}{os.pathsep}{os.environ['PATH']}"}


CLASS_ATTR = ("class_attr_if", "class_attr_try", "class_attr_for", "class_attr_while", "class_attr_with",
              "class_attr_match", "class_attr_loop", "class_attr_unpack", "class_attr_walrus")
INIT_SUBCLASS = ("init_subclass_if", "init_subclass_try")
ALIAS_GUARD = ("alias_guard_4", "alias_guard_5")


class R9Acceptance(unittest.TestCase):
    """Codex's acceptance tests (test_r9_acceptance.py), over every fixture of each finding, with file and line."""

    def test_controls(self):
        self.assertEqual(fixture_points("plain"), 8)
        self.assertEqual(fixture_points("class_attr_direct"), 0)
        self.assertEqual(fixture_points("init_subclass_direct"), 0)
        self.assertEqual(fixture_points("alias_guard_3"), 0)
        self.assertTrue(KG.refuses("sh -c 'git push'"))
        self.assertFalse(KG.refuses("sh -c 'git status'"))

    def test_compound_class_attribute_binding_withholds_credit(self):
        for n in CLASS_ATTR:
            with self.subTest(fixture=n):
                self.assertEqual(fixture_points(n), 0)

    def test_long_parameter_alias_withholds_credit(self):
        for n in ALIAS_GUARD + tuple(f"alias_{i}" for i in range(8)) + ("alias_runtime_4", "alias_runtime_5",
                                                                         "alias_runtime_6"):
            with self.subTest(fixture=n):
                self.assertEqual(fixture_points(n), 0)

    def test_conditional_init_subclass_withholds_credit(self):
        for n in INIT_SUBCLASS:
            with self.subTest(fixture=n):
                self.assertEqual(fixture_points(n), 0)

    def test_tab_separated_nested_command_is_refused(self):
        self.assertTrue(KG.refuses("sh -c 'git\tpush'"))

    def test_the_reasons_name_the_file_and_line(self):
        self.assertIn("patch.py:12", fixture_reasons("class_attr_if"))      # the store through self.m
        self.assertIn("patch.py:8", fixture_reasons("alias_guard_4"))
        self.assertIn("patch.py:", fixture_reasons("init_subclass_if"))


BOOT_SUBPROCESS = ("import sys, types, subprocess\nagents = types.ModuleType('agents'); agents.Agent = lambda **kw: kw\n"
                   "sys.modules['agents'] = agents\nv = types.ModuleType('vendorlib'); v.load = lambda: subprocess\n"
                   "sys.modules['vendorlib'] = v\nimport agent\nprint('TOOL_RESULT', agent.run('printf ordinary'))\n")
BOOT_GUARD = ("import sys, types, kit_guard\nm = types.ModuleType('agents'); m.Agent = lambda **k: k\n"
              "sys.modules['agents'] = m\nv = types.ModuleType('vendorlib'); v.load = lambda: kit_guard\n"
              "sys.modules['vendorlib'] = v\nprint('BEFORE', kit_guard.refuses('git -C ordinary push'))\nimport agent\n"
              "print('AFTER', kit_guard.refuses('git -C ordinary push'))\nprint('TOOL', agent.run('git -C ordinary push'))\n")


class R9Runtime(unittest.TestCase):
    """What actually runs, in a fresh interpreter, on constructed files in a throwaway folder."""

    def test_the_class_attribute_and_init_subclass_fixtures_return_the_sentinel(self):
        for n in CLASS_ATTR + ("class_attr_direct",) + INIT_SUBCLASS + ("init_subclass_direct",):
            with self.subTest(fixture=n), FixtureCopy(n) as d:
                p = subprocess.run([sys.executable, "-B", "-c", BOOT_SUBPROCESS], cwd=d, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(SENTINEL, p.stdout)            # the threat is real; the audit must not credit it

    def test_the_long_alias_fixtures_switch_the_helper_off(self):
        for n in ("alias_guard_3",) + ALIAS_GUARD:
            with self.subTest(fixture=n), FixtureCopy(n) as d:
                p = subprocess.run([sys.executable, "-B", "-c", BOOT_GUARD], cwd=d, capture_output=True, text=True,
                                   env=stand_in_git(d))
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn("BEFORE True", p.stdout)
                self.assertIn("AFTER False", p.stdout)
                self.assertIn("CONSTRUCTED_GIT:-C ordinary push", p.stdout)

    def test_a_tab_reaches_the_inner_git(self):
        d = Path(tempfile.mkdtemp())
        try:
            for c in ("sh -c 'git\tpush'", "env -S'git\tpush'"):
                p = subprocess.run(["sh", "-c", c], cwd=d, capture_output=True, text=True, env=stand_in_git(d))
                if c.startswith("env") and p.returncode:
                    continue                                 # an env without -S: nothing to show
                with self.subTest(command=c):
                    self.assertIn("CONSTRUCTED_GIT:push", p.stdout)
                    self.assertTrue(KG.refuses(c))
        finally:
            shutil.rmtree(d)


# ------------------------------------------------------------------ the namespace class: rule x compound wrapper x depth
def _indent(text, n=4):
    return "".join(" " * n + line if line.strip() else line for line in text.splitlines(True))


# Each wrapper puts a block one compound statement deeper; none of them makes a namespace.
WRAPPERS = {
    "if": lambda b: "if True:\n" + _indent(b),
    "else": lambda b: "if False:\n    pass\nelse:\n" + _indent(b),
    "elif": lambda b: "if False:\n    pass\nelif True:\n" + _indent(b),
    "try": lambda b: "try:\n" + _indent(b) + "except Exception:\n    pass\n",
    "except": lambda b: "try:\n    pass\nexcept Exception:\n" + _indent(b),
    "try/else": lambda b: "try:\n    pass\nexcept Exception:\n    pass\nelse:\n" + _indent(b),
    "finally": lambda b: "try:\n    pass\nfinally:\n" + _indent(b),
    "except*": lambda b: "try:\n" + _indent(b) + "except* Exception:\n    pass\n",
    "for": lambda b: "for _ in range(1):\n" + _indent(b),
    "for/else": lambda b: "for _ in range(1):\n    pass\nelse:\n" + _indent(b),
    "while": lambda b: "while True:\n" + _indent(b) + "    break\n",
    "while/else": lambda b: "while False:\n    pass\nelse:\n" + _indent(b),
    "with": lambda b: "with open(__file__):\n" + _indent(b),
    "match": lambda b: "match 1:\n    case 1:\n" + _indent(b, 8),
}
WRAPPER_NAMES = list(WRAPPERS)


def nestings():
    """(label, wrap) for every wrapper at depth 1, and every wrapper as the outer one of a 2- and a 3-deep nest (the
    inner ones the next wrappers in the list), so each wrapper is seen at each depth."""
    for depth in (1, 2, 3):
        for i, outer in enumerate(WRAPPER_NAMES):
            chain = [WRAPPER_NAMES[(i + k) % len(WRAPPER_NAMES)] for k in range(depth)]

            def wrap(b, chain=chain):
                for w in reversed(chain):
                    b = WRAPPERS[w](b)
                return b
            yield " > ".join(chain), wrap


TOOL_AGENT = ("import subprocess\nfrom agents import Agent\nfrom kit_guard import refuses\nimport patch\n"
              "def run(command):\n    if refuses(command):\n        return 'denied'\n"
              "    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout\n"
              "agent = Agent(name='w', tools=[run])\n")
REPL = "def replacement(*a, **k):\n    return None\n"

# Rule F1 self attribute (Index.attr_safe): a binding of `m` in K's namespace, in any form.
ATTR_BINDINGS = {
    "assignment": "m = vendorlib.load()\n",
    "annotated": "m: object = vendorlib.load()\n",
    "walrus": "(m := vendorlib.load())\n",
    "for target": "for m in [vendorlib.load()]:\n    pass\n",
    "with as": "with vendorlib.load() as m:\n    pass\n",
    "unpacking": "m, = [vendorlib.load()]\n",
    "chained": "m = n = vendorlib.load()\n",
    "import as": "import subprocess as m\n",
    "from import": "from vendorlib import m\n",
    "match capture": "match vendorlib.load():\n    case m:\n        pass\n",
    "augmented": "m = []\nm += vendorlib.load()\n",
}
ATTR_USES = {"store": "self.m.run = replacement\n", "mutate": "self.m.handlers.clear()\n"}


def attr_patch(block, use):
    return ("import vendorlib\n" + REPL + "class Other:\n    m = []\nclass K:\n" + _indent(block) +
            "    def change(self):\n" + _indent(use, 8) + "K().change()\n")


# Rule F1 closed class (_class_closed): __init_subclass__ of a repo base, in any binding form or first-parameter name.
HOOKS = {
    "def cls": "def __init_subclass__(cls):\n    cls.change(vendorlib.load())\n",
    "def self": "def __init_subclass__(self):\n    self.change(vendorlib.load())\n",
    "def klass": "def __init_subclass__(klass, **kw):\n    klass.change(vendorlib.load())\n",
    "assigned": "__init_subclass__ = classmethod(hook)\n",
}
HOOK_FN = "def hook(cls):\n    cls.change(vendorlib.load())\n"


def hook_patch(block, indirect):
    base = "class Base0:\n" + _indent(block) + ("class Base(Base0):\n    pass\n" if indirect else "")
    if not indirect:
        base = base.replace("class Base0:", "class Base:")
    return ("import vendorlib\n" + REPL + (HOOK_FN if "hook)" in block else "") + base +
            "class K(Base):\n    def change(self):\n        self.run = replacement\n")


# Rule F1 class body naming a method (Index._class_open).
def named_method_patch(block):
    return (REPL + "class K:\n    def change(self):\n        self.run = replacement\n" + _indent(block) +
            "K().change()\n")


# Rule F1 exec family: a function named eval binds the name, except a method in a class namespace.
def eval_patch(block, where):
    if where == "class":
        return "class Model:\n" + _indent(block) + "Model().eval()\n"
    if where == "function":
        return "def outer():\n" + _indent(block) + "    return 1\nouter()\n"
    return block


# Rule F1 name resolution (_ModuleUses.scope_binds): a mutated local is read in its own namespace.
def local_patch(block, nested_control=False):
    if nested_control:
        return ("import vendorlib\ndef f():\n    p = []\n    def g():\n" + _indent(block, 8) +
                "        return p\n    p.append(1)\n    return g\nf()\n")
    return "import vendorlib\ndef f(m):\n" + _indent(block) + "    p.handlers.clear()\nf(vendorlib.load())\n"


# Rule F5 (R8-03): options returned from a function in a class namespace.
SDK_HEAD = ("from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, ClaudeSDKClient\nfrom kit_guard import refuses\n"
            "async def gate(data, tool_use_id, context):\n    if refuses(data['tool_input']):\n"
            "        return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny'}}\n"
            "    return {}\n")
OPTS = ("ClaudeAgentOptions(tools=['Bash'], allowed_tools=['Bash'], "
        "hooks={'PreToolUse': [HookMatcher(matcher='Bash', hooks=[gate])]})")
MAKE = {"inline": f"def make():\n    return {OPTS}\n", "through a local": f"def make():\n    opts = {OPTS}\n    return opts\n"}


class R9Namespace(unittest.TestCase):
    """(every rule that reads a namespace or bindings) x (every compound wrapper, nested 1 to 3 deep)."""

    def score_patch(self, text):
        ast.parse(text)
        return fast_score({"agent.py": TOOL_AGENT, "patch.py": text})

    def test_self_attribute_bindings_in_a_class_namespace(self):
        n = 0
        for wl, wrap in nestings():
            for bl, block in ATTR_BINDINGS.items():
                for ul, use in ATTR_USES.items():
                    text = attr_patch(wrap(block), use)
                    with self.subTest(wrapper=wl, binding=bl, use=ul):
                        self.assertEqual(self.score_patch(text), 0, text)
                        n += 1
        self.assertGreater(n, 900)

    def test_safe_self_attributes_and_function_locals_keep_credit(self):
        for wl, wrap in nestings():
            for label, text in (
                    ("a list, wrapped", "class K:\n" + _indent(wrap("m = []\n")) +
                     "    def change(self):\n        self.m.append(1)\nK().change()\n"),
                    ("a method's local is not a class attribute",
                     "import vendorlib\nclass K:\n    m = []\n    def helper(self):\n" +
                     _indent(wrap("m = vendorlib.load()\n"), 8) + "        return m\n"
                     "    def change(self):\n        self.m.append(1)\nK().change()\n")):
                with self.subTest(wrapper=wl, case=label):
                    self.assertEqual(self.score_patch(text), 8, text)

    def test_init_subclass_in_a_base_namespace(self):
        for wl, wrap in nestings():
            for hl, hook in HOOKS.items():
                for indirect in (False, True):
                    text = hook_patch(wrap(hook), indirect)
                    with self.subTest(wrapper=wl, hook=hl, indirect=indirect):
                        self.assertEqual(self.score_patch(text), 0, text)

    def test_bases_without_a_hook_keep_credit(self):
        for wl, wrap in nestings():
            text = hook_patch(wrap("def other(cls):\n    return 1\n"), True)
            with self.subTest(wrapper=wl):
                self.assertEqual(self.score_patch(text), 8, text)

    def test_a_class_body_naming_its_method(self):
        for wl, wrap in nestings():
            for label, block, want in (("alias = change", "alias = change\n", 0), ("(change,)", "(change,)\n", 0),
                                       ("control: alias = 1", "alias = 1\n", 8)):
                text = named_method_patch(wrap(block))
                with self.subTest(wrapper=wl, case=label):
                    self.assertEqual(self.score_patch(text), want, text)

    def test_the_exec_family_name_binding(self):
        for wl, wrap in nestings():
            for where, want in (("class", 8), ("function", 0), ("module", 0)):
                text = eval_patch(wrap("def eval(self=None):\n    return 1\n"), where)
                with self.subTest(wrapper=wl, where=where):
                    self.assertEqual(self.score_patch(text), want, text)

    def test_a_mutated_local_is_resolved_in_its_own_namespace(self):
        for wl, wrap in nestings():
            for label, block in (("an outside result", "p = vendorlib.load()\n"), ("a parameter's", "p = m\n"),
                                 ("a parameter's attribute", "p = m.x\n")):
                text = local_patch(wrap(block))
                with self.subTest(wrapper=wl, binding=label):
                    self.assertEqual(self.score_patch(text), 0, text)
            text = local_patch(wrap("p = vendorlib.load()\n"), nested_control=True)
            with self.subTest(wrapper=wl, binding="a nested function's own local (control)"):
                self.assertEqual(self.score_patch(text), 8, text)

    def test_options_from_a_class_namespace_function(self):
        for wl, wrap in nestings():
            for ml, make in MAKE.items():
                src = SDK_HEAD + "class App:\n" + _indent(wrap(make)) + "client = ClaudeSDKClient(options=App.make())\n"
                ast.parse(src)
                with self.subTest(wrapper=wl, make=ml):
                    self.assertEqual(fast_score({"agent.py": src}), 0, src)
                ctl = SDK_HEAD + "def main():\n" + _indent(wrap(make)) + \
                    "    return ClaudeSDKClient(options=make())\nclient = main()\n"
                with self.subTest(wrapper=wl, make=ml, control="in a function"):
                    self.assertEqual(fast_score({"agent.py": ctl}), 8, ctl)


# ------------------------------------------------------------------ R8-02 completed: aliases of what a parameter holds
ALIAS_FORMS = {        # p: something m (a non-exempt parameter) holds, or may hold
    "assignment": "p = m.handlers\n",
    "annotated": "p: list = m.handlers\n",
    "walrus": "(p := m.handlers)\n",
    "chained": "p = q = m.handlers\n",
    "if-expression": "p = m.handlers if m else None\n",
    "or": "p = None or m.handlers\n",
    "getattr": "p = getattr(m, 'handlers')\n",
    "dict get": "p = m.get('handlers')\n",
    "for element": "for p in [m.handlers]:\n    pass\n",
    "for over it": "for p in m.handlers:\n    pass\n",
    "with as": "with m.handlers as p:\n    pass\n",
    "unpacking": "p, q = m.handlers, 1\n",
    "starred": "*p, = m.handlers\n",
    "match capture": "match m.handlers:\n    case p:\n        pass\n",
    "next(iter())": "p = next(iter(m.handlers))\n",
    "nonlocal": None,
    "global": None,
}
MUTATIONS = {"method": "p.clear()\n", "item store": "p[0] = 1\n", "item delete": "del p[0]\n",
             "attribute store": "p.x = 1\n", "setattr": "setattr(p, 'x', 1)\n", "deeper method": "p.x.clear()\n"}


def alias_patch(form, mutation, chain=0):
    if form == "global":
        return ("import vendorlib\ndef bind(m):\n    global p\n    p = m.handlers\ndef change():\n" +
                _indent(mutation) + "bind(vendorlib.load())\nchange()\n")
    if form == "nonlocal":
        return ("import vendorlib\ndef change(m):\n    p = None\n    def bind():\n        nonlocal p\n"
                "        p = m.handlers\n    bind()\n" + _indent(mutation) + "change(vendorlib.load())\n")
    links = "".join(f"p{i + 1} = p{i}\n" for i in range(chain))
    block = re.sub(r"\bp\b", "p0", ALIAS_FORMS[form]) if chain else ALIAS_FORMS[form]
    last = f"p{chain}" if chain else "p"
    return ("import vendorlib\ndef change(m):\n" + _indent(block + links) +
            _indent(re.sub(r"\bp\b", last, mutation)) + "change(vendorlib.load())\n")


OUTSIDE_RESULTS = {    # a local bound to what an outside call returned (it may be a module), changed through it
    "module level": "import vendorlib\np = vendorlib.load()\np.handlers.clear()\n",
    "in a function": "import vendorlib\ndef f():\n    p = vendorlib.load()\n    p.handlers.clear()\nf()\n",
    "item store": "import vendorlib\np = vendorlib.load()\np.handlers[0] = 1\n",
    "through an alias": "import vendorlib\np = vendorlib.load()\nq = p\nq.handlers.clear()\n",
    "a rebound self": "import vendorlib\nclass Other:\n    handlers = []\nclass K:\n    def change(self):\n"
                      "        self = vendorlib.load()\n        self.handlers.clear()\nK().change()\n",
    "a module-level self": "import vendorlib\nclass Other:\n    handlers = []\nself = vendorlib.load()\nclass C:\n"
                           "    def m(self):\n        pass\ndef g():\n    self.handlers.clear()\ng()\n",
    "global binding elsewhere": "import vendorlib\ndef f():\n    global p\n    p = vendorlib.load()\ndef g():\n"
                                "    p.handlers.clear()\nf()\ng()\n",
}
ALIAS_CONTROLS = {     # ordinary local collections: credit stays
    "a new list": "def f(m):\n    out = []\n    out.append(m)\n    return out\n",
    "a new dict": "def f(m):\n    d = {}\n    d['k'] = m\n    return d\n",
    "a copy by list()": "def f(m):\n    items = list(m)\n    items.append(1)\n    return items\n",
    "a copy by dict()": "def f(m):\n    d = dict(m)\n    d['k'] = 1\n    return d\n",
    "a sorted copy": "def f(m):\n    items = sorted(m)\n    items.append(1)\n    return items\n",
    "a comprehension": "def f(m):\n    items = [x for x in m]\n    items.append(1)\n    return items\n",
    "a parsed document": "import json\ndef f(s):\n    data = json.loads(s)\n    data['k'] = 1\n    return data\n",
    "a counter": "def f(m):\n    n = 0\n    for x in m:\n        n += 1\n    return n\n",
    "a module-level list": "HANDLERS = []\ndef add(h):\n    HANDLERS.append(h)\n",
    "a set built from a range": "def f():\n    s = set()\n    for i in range(3):\n        s.add(i)\n    return s\n",
}


class R9Alias(unittest.TestCase):
    """R8-02 completed: a mutation of anything held by a non-exempt repo parameter, through any chain of local
    aliases and any binding form, withholds credit; so does a change through a local bound to an outside result."""

    def check(self, label, text, want):
        ast.parse(text)
        with self.subTest(case=label):
            self.assertEqual(fast_score({"agent.py": TOOL_AGENT, "patch.py": text}), want, text)

    def test_every_alias_form_and_mutation_withholds_credit(self):
        for fl in ALIAS_FORMS:
            for ml, mutation in MUTATIONS.items():
                self.check(f"{fl} / {ml}", alias_patch(fl, mutation), 0)

    def test_chains_of_any_length(self):
        for length in list(range(0, 13)) + [30, 31, 32, 33, 34, 40]:
            for fl in ("assignment", "walrus", "for element", "if-expression"):
                self.check(f"{fl} then {length} links", alias_patch(fl, "p.clear()\n", length), 0)

    def test_cycles_still_reach_the_parameter(self):
        text = ("import vendorlib\ndef change(m):\n    p = None\n    q = None\n    for _ in range(2):\n"
                "        p = q\n        q = p\n        q = m.handlers\n    p.clear()\nchange(vendorlib.load())\n")
        self.check("p = q; q = p; q = m.handlers", text, 0)

    def test_a_local_bound_to_an_outside_result(self):
        for label, text in OUTSIDE_RESULTS.items():
            self.check(label, text, 0)

    def test_ordinary_local_collections_keep_credit(self):
        for label, text in ALIAS_CONTROLS.items():
            self.check(label, text, 8)


# ------------------------------------------------------------------ R9-04: the helper's whitespace table
MEMBERS = {"git push": ["git", "push"], "git clean": ["git", "clean", "-fd"], "git reset --hard": ["git", "reset", "--hard"],
           "rm -rf": ["rm", "-rf", "x"], "rm --recursive": ["rm", "--recursive", "x"],
           "git -c alias": ["git", "-c", "alias.x=!y", "x"]}
BLANKS = {"space": " ", "tab": "\t"}
SEPARATORS = {";": ";", "&": "&", "|": "|", "&&": "&&", "||": "||", "newline": "\n", "( )": None}
CONTROLS = {f"U+{c:04X}": chr(c) for c in list(range(0x00, 0x09)) + list(range(0x0B, 0x20)) + [0x7F]}
NON_ASCII_SPACES = {f"U+{c:04X}": chr(c) for c in (0x85, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
                                                  0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F,
                                                  0x205F, 0x3000, 0x180E, 0x200B, 0xFEFF)}


def nest_forms(cmd, depth):
    """The command nested `depth` levels deep, as a shell string, an argument vector and an `env -S` string."""
    if depth == 0:     # an argument vector of separator text runs a program named `(git`: no argv form for it
        return {"shell string": cmd, **({} if any(c in cmd for c in ";&|()\n") else
                                        {"argv": cmd.split(" ") if " " in cmd else [cmd]})}
    inner = cmd
    for _ in range(depth - 1):
        inner = "sh -c " + shlex.quote(inner)
    return {"shell string": "sh -c " + shlex.quote(inner), "argv": ["sh", "-c", inner],
            "env -S": "env -S" + shlex.quote(inner), "env --split-string": "env --split-string=" + shlex.quote(inner)}


class R9ShellWhitespace(unittest.TestCase):
    """Each blank, separator and control character x each destructive member x nesting depth 0 to 6 x form."""

    def test_destructive_members_joined_by_blanks_or_after_separators(self):
        n = 0
        for ml, words in MEMBERS.items():
            cmds = {f"words joined by {bl}": b.join(words) for bl, b in BLANKS.items()}
            cmds.update({f"after {sl}": ("(" + " ".join(words) + ")" if s is None else "true" + s + "\t".join(words))
                         for sl, s in SEPARATORS.items()})
            for cl, cmd in cmds.items():
                for depth in range(7):
                    for fl, value in nest_forms(cmd, depth).items():
                        n += 1
                        with self.subTest(member=ml, how=cl, depth=depth, form=fl):
                            self.assertTrue(KG.refuses(value), repr(value))
        self.assertGreater(n, 1000)

    def test_any_other_control_character_or_non_ascii_space_is_refused(self):
        for chars in (CONTROLS, NON_ASCII_SPACES):
            for cl, c in chars.items():
                for base in ("echo{c}hello", "git{c}push", "cat{c}README.md"):
                    for depth in range(7):
                        for fl, value in nest_forms(base.format(c=c), depth).items():
                            with self.subTest(char=cl, base=base, depth=depth, form=fl):
                                self.assertTrue(KG.refuses(value), repr(value))

    def test_benign_shallow_commands_with_blanks_stay_allowed(self):
        for cmd in ("echo hello world", "echo\thello\tworld", "git\tstatus", "ls -la\nls", "git status; git log",
                    "echo a | wc -l", "(git status)"):
            for depth in range(4):
                for fl, value in nest_forms(cmd, depth).items():
                    if fl == "argv" and "\n" in cmd:
                        continue
                    with self.subTest(cmd=cmd, depth=depth, form=fl):
                        self.assertFalse(KG.refuses(value), repr(value))

    def test_a_crlf_line_end_is_read_as_a_newline(self):
        self.assertFalse(KG.refuses("echo hello\r\n"))
        self.assertTrue(KG.refuses("git push\r\n"))
        self.assertTrue(KG.refuses("git\rpush"))


# ------------------------------------------------------------------ the rule code reads namespaces only through helpers
AUDIT_SRC = ROOT / "plugins/harness-audit/skills/audit/scripts/audit.py"
NAMESPACE_HELPERS = {"_parents", "_parents_of", "_context", "_in_own", "_namespace", "_enclosing_function",
                     "_param_owner", "_own_nodes", "_binding_names", "_bindings", "_lookup", "_binding_source",
                     "_store_value"}


class R9OneWalker(unittest.TestCase):
    def test_no_rule_reads_a_parent_or_a_class_body_directly(self):
        """Outside the namespace helpers, no `parents.get(...)`, `parents[...]`, `.parent` of a node, or a loop over
        a class's `.body`: every rule asks the helpers for the enclosing namespace or the bindings of a name."""
        tree = ast.parse(AUDIT_SRC.read_text())
        bad = []

        def visit(node, fn):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = node.name
            if fn not in NAMESPACE_HELPERS:
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                    recv = node.func.value
                    name = recv.id if isinstance(recv, ast.Name) else recv.attr if isinstance(recv, ast.Attribute) \
                        else recv.func.id if isinstance(recv, ast.Call) and isinstance(recv.func, ast.Name) else ""
                    if "parents" in name or name in ("mp",):
                        bad.append(f"{node.lineno} {fn}: {ast.unparse(node)[:60]}")
                if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and "parents" in node.value.id:
                    bad.append(f"{node.lineno} {fn}: {ast.unparse(node)[:60]}")
                if isinstance(node, (ast.For, ast.comprehension)) and isinstance(node.iter, ast.Attribute) and node.iter.attr == "body" and \
                        isinstance(node.iter.value, ast.Name) and node.iter.value.id in ("n", "cls", "bc", "c", "k"):
                    bad.append(f"{getattr(node, 'lineno', getattr(node.iter, 'lineno', 0))} {fn}: for ... in "
                               f"{ast.unparse(node.iter)}")
            for ch in ast.iter_child_nodes(node):
                visit(ch, fn)
        visit(tree, None)
        self.assertEqual(bad, [], "\n".join(bad))


if __name__ == "__main__":
    unittest.main(verbosity=2)
