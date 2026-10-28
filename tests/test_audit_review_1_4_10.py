"""The independent audit-side review of 1.4.10 before packaging (about 125 audits in about 52 tool calls; harmless
stand-ins for the runtime proofs, which the reviewer ran and which are not repeated here). Each case is one the
reviewer reported against the written CANONICAL_FORMS; the reviewer's case number is in the test name."""
import os
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import HELPER, Repo
from test_audit_r9 import AUDIT, TOOL_AGENT, fast_points, fast_score

HEAD = "import subprocess\nfrom pathlib import Path\nfrom agents import Agent\nfrom kit_guard import refuses\n"
RUN = ("def run(command):\n    if refuses(command):\n        return 'denied'\n"
       "    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout\n")


def patch(text):
    return fast_score({"agent.py": TOOL_AGENT, "patch.py": text})


def agent(extra, tools="run"):
    return fast_score({"agent.py": HEAD + RUN + extra + f"agent = Agent(name='w', tools=[{tools}])\n"})


class AuditReview1410(unittest.TestCase):
    def check(self, label, got, want):
        with self.subTest(case=label):
            self.assertEqual(got, want)

    def test_01_a_comprehension_in_a_class_body_reads_the_module_name(self):
        for body in ("    z = [setattr(p, 'run', 1) for _ in (1,)]\n", "    z = [p.handlers.clear() for _ in (1,)]\n",
                     "    z = list(p.handlers.clear() for _ in (1,))\n", "    z = [1 for _ in (1,) if p.handlers.clear()]\n"):
            self.check(body, patch("import vendorlib\np = vendorlib.load()\nclass C:\n    p = []\n" + body), 0)

    def test_02_a_class_body_name_may_be_the_module_name(self):
        for body in ("    setattr(p, 'run', 1)\n    p = []\n", "    if False:\n        p = []\n    p.run = 1\n",
                     "    p = []\n    del p\n    p.run = 1\n"):
            self.check(body, patch("import vendorlib\np = vendorlib.load()\nclass C:\n" + body), 0)

    def test_03_a_decorated_def_is_not_a_safe_class_attribute(self):
        prop = ("import vendorlib\nclass Base:\n    @property\n    def h(self):\n        return vendorlib.load()\n"
                "    def add(self, v):\n        self.h.run = v\nBase().add(1)\n")
        sub = ("import vendorlib\nclass Base:\n    def add(self, v):\n        self.h.run = v\nclass Sub(Base):\n"
               "    @property\n    def h(self):\n        return vendorlib.load()\nSub().add(1)\n")
        wrap = ("import vendorlib\nclass Base:\n    @vendorlib.wrap\n    def h(self):\n        pass\n"
                "    def add(self, v):\n        self.h.run = v\nBase().add(1)\n")
        for label, text in (("property", prop), ("property in a subclass", sub), ("outside decorator", wrap)):
            self.check(label, patch(text), 0)

    def test_04_a_field_of_a_decorated_class_is_bound_by_its_constructor(self):
        for call in ("Box(items=vendorlib.load())", "Box(vendorlib.load())"):
            text = ("import vendorlib\nfrom dataclasses import dataclass\n@dataclass\nclass Box:\n    items: object = None\n"
                    "    def put(self, v):\n        self.items.run = v\n" + call + ".put(1)\n")
            self.check(call, patch(text), 0)

    def test_05_in_place_changes_through_augmented_assignment_and_unbound_methods(self):
        for label, text in (
                ("|= on an outside result's attribute", "import vendorlib\np = vendorlib.load().modules\np |= {'x': 1}\n"),
                ("dict.update", "import vendorlib\ndict.update(vendorlib.load().modules, {'x': 1})\n"),
                ("+= on an outside result's attribute", "import vendorlib\np = vendorlib.load().handlers\np += [1]\n"),
                ("list.append", "import vendorlib\nlist.append(vendorlib.load().path, '/x')\n"),
                ("+= on a parameter's attribute", "import vendorlib\ndef f(m):\n    p = m.handlers\n    p += [1]\nf(vendorlib.load())\n"),
                ("list.append on a parameter", "import vendorlib\ndef f(m):\n    list.append(m.path, '/x')\nf(vendorlib.load())\n")):
            self.check(label, patch(text), 0)
        self.check("control: += on a new list", patch("def f():\n    p = []\n    p += [1]\n    return p\n"), 8)

    def test_06_an_operator_result_is_not_a_safe_value(self):
        for expr in ("vendorlib.handle() + 0", "-vendorlib.handle()", "vendorlib.handle() == 0"):
            self.check(expr, patch(f"import vendorlib\np = {expr}\np.run = 1\n"), 0)
        self.check("control: a number", patch("class K:\n    pass\np = K()\nq = 1 + 2\np.run = q\n"), 8)

    def test_07_a_python_file_the_walk_does_not_read_stops_the_audit(self):
        outside = Path(tempfile.mkdtemp())
        (outside / "evil.py").write_text("import sys\nsys.path.append('/x')\n")
        (outside / "pkg").mkdir()
        (outside / "pkg" / "__init__.py").write_text("")
        try:
            for label, link in (("a linked file", "patch.py"), ("a linked folder", "pkgdir")):
                files = {"agent.py": TOOL_AGENT, "kit_guard.py": HELPER}
                if label == "a linked folder":
                    files["patch.py"] = "import pkgdir\n"
                with Repo(files) as d:
                    os.symlink(outside / ("evil.py" if link == "patch.py" else "pkg"), d / link)
                    self.check(label, fast_points(d), 0)
        finally:
            for p in sorted(outside.rglob("*"), reverse=True):
                p.unlink() if p.is_file() else p.rmdir()
            outside.rmdir()

    def test_08_a_tool_class_with_two_entry_points_is_not_followed(self):
        two = ("class Shell:\n    def run(self, command):\n        if refuses(command):\n            return 'denied'\n"
               "        return subprocess.run(command, shell=True).returncode\n"
               "    def __call__(self, command):\n        return subprocess.run(command, shell=True).returncode\n")
        base = ("class B:\n    def __call__(self, command):\n        return subprocess.run(command, shell=True).returncode\n"
                "class Shell(B):\n    def run(self, command):\n        if refuses(command):\n            return 'denied'\n"
                "        return subprocess.run(command, shell=True).returncode\n")
        for label, extra in (("run and __call__", two), ("an inherited __call__", base)):
            self.check(label, fast_score({"agent.py": HEAD + extra + "agent = Agent(name='w', tools=[Shell()])\n"}), 0)

    def test_09_a_path_method_outside_the_lists_on_the_input(self):
        write_text = agent("def other(name):\n    Path(name).write_text('x')\n    return 'ok'\n", "run, other")
        self.assertEqual(write_text, 3)               # a write tool: G1 and G3 missing (F6: the helper reads text)
        for meth in ("symlink_to('id_dsa')", "hardlink_to('id_dsa')", "copy('x')"):
            self.check(meth, agent(f"def other(name):\n    Path(name).{meth}\n    return 'ok'\n", "run, other"), write_text)
        self.check("control: exists()", agent("def other(name):\n    return Path(name).exists()\n", "run, other"), 8)

    def test_10_an_unmodelled_path_chain_with_a_fixed_target(self):
        for body in ("return (Path('x').parent / 'server.key').read_text()",
                     "return (Path('.') / 'a' / '..' / 'b' / '..' / 'c' / '../server.key').read_text()",
                     "p = Path('x').parent\n    return (p / 'server.key').read_text()"):
            self.check(body, agent(f"def peek():\n    {body}\n", "run, peek"), 0)

    def test_11_a_fixed_command_rebound_through_global(self):
        extra = ("CMD = 'ls'\ndef setup():\n    global CMD\n    CMD = 'rm -rf data'\nsetup()\n"
                 "def peek():\n    return subprocess.run(CMD, shell=True, capture_output=True, text=True).stdout\n")
        self.check("global CMD", agent(extra, "run, peek"), 0)

    def test_12_standard_functions_that_change_their_first_argument(self):
        for call in ("bisect.insort(vendorlib.load().path, '')", "operator.iadd(vendorlib.load().handlers, [1])",
                     "heapq.heappush(vendorlib.load().handlers, 1)", "random.shuffle(vendorlib.load().handlers)"):
            mod = call.split(".")[0]
            self.check(call, patch(f"import vendorlib, {mod}\n{call}\n"), 0)
        self.check("on a parameter", patch("import vendorlib, heapq\ndef f(m):\n    heapq.heappush(m.path, '/x')\n"
                                           "f(vendorlib.load())\n"), 0)
        self.check("control: on a new list", patch("import heapq\nh = []\nheapq.heappush(h, 1)\n"), 8)

    def test_13_a_comprehension_target_is_not_a_class_attribute(self):
        text = ("class Box:\n    def __init__(self):\n        self.items = []\n    def add(self, v):\n"
                "        self.items.append(v)\nBox().add(1)\nclass Other:\n    names = [items for items in ('a', 'b')]\n")
        self.check("a comprehension target", patch(text), 8)

    def test_14_a_re_export_past_the_bound_names_it(self):
        files = {"agent.py": "from agents import Agent\nfrom r1 import run\nagent = Agent(name='w', tools=[run])\n",
                 "r1.py": "from r2 import run\n", "r2.py": "from r3 import run\n", "r3.py": "from r4 import run\n",
                 "r4.py": HEAD + RUN, "kit_guard.py": HELPER}
        with Repo(files) as d:
            rep = AUDIT.audit(d)
        ev = " ".join(c["evidence"] for c in rep.checks if c["id"] in ("G1", "G2", "G3"))
        self.assertIn("stopped at a bound", ev)
        self.assertIn("re-export", " ".join(t for _, t in AUDIT.CANONICAL_FORMS))
        self.assertIn("3 re-export hops", dict(AUDIT.CANONICAL_FORMS)["F7 Everything else"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
