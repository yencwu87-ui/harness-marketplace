"""1.4.5 independent review: seams in the checker that an independent reviewer pointed at before packaging.

The reviewer agent declined to build working bypasses and named four seams instead. Each is written here as the
invariant the audit must hold, with a positive beside it:
  1. the helper the audit hashes must be the module Python imports (no package, compiled or second copy that wins);
  2. run-time tampering through method calls (`__dict__.update`, `sys.modules`, `importlib.reload`) is tampering;
  3. a capability call binds a helper refusal only when it runs what the name says, with options that cannot change
     what runs (a patched or rebound `subprocess.run`, `executable=`, `env=`, `opener=`, `preexec_fn=`);
  4. files the index skips (test-named modules, sitecustomize, .pth) can still change things at run time.
"""
import unittest

from test_audit_fairness import GUARD, HELPER, Repo, audit, guards, points

TOOL = ("import os, subprocess, requests\nfrom kit_guard import refuses\nfrom agents import Agent\n{module}"
        "def run(command):\n    if refuses(command):\n        return 'denied'\n{body}agent = Agent(name='w', tools=[run])\n")
SHELL = "    return subprocess.run(command, shell=True).returncode\n"


def score(files):
    files = dict(files)
    files.setdefault("kit_guard.py", HELPER)
    with Repo(files) as d:
        rep = audit(d)
        return points(rep), {c: g["status"] for c, g in guards(rep).items()}


def tool(body=SHELL, module=""):
    return {"agent.py": TOOL.format(module=module, body=body)}


class ReviewSeams(unittest.TestCase):
    def check(self, label, files, want=0):
        with self.subTest(case=label):
            pts, st = score(files)
            self.assertEqual(pts, want, (st, files))

    def test_positive(self):
        self.check("the plain helper tool", tool(), want=8)

    def test_1_the_hashed_helper_is_the_one_imported(self):
        self.check("a kit_guard package beside the file", dict(tool(), **{"kit_guard/__init__.py": "def refuses(v):\n    return False\n"}))
        self.check("a compiled extension beside the file", dict(tool(), **{"kit_guard.so": "not really a library"}))
        self.check("a sourceless kit_guard.pyc beside the file", dict(tool(), **{"kit_guard.pyc": "x"}))
        self.check("another kit_guard.py elsewhere in the repo", dict(tool(), **{"lib/kit_guard.py": "def refuses(v):\n    return False\n"}))
        self.check("an identical second copy is fine", dict(tool(), **{"lib/kit_guard.py": HELPER}), want=8)

    def test_2_tampering_through_method_calls(self):
        cases = {"__dict__.update on the helper module": "import kit_guard as _k\n_k.__dict__.update(refuses=len)\n",
                 "sys.modules.update": "import sys\nsys.modules.update({})\n",
                 "importlib.reload": "import importlib, kit_guard as _k\nimportlib.reload(_k)\n",
                 "a module's __dict__ through vars-like access": "import re\nre.__dict__.setdefault('x', 1)\n"}
        for label, code in cases.items():
            self.check(label, dict(tool(), **{"other.py": code}))

    def test_3_the_capability_runs_what_its_name_says(self):
        self.check("subprocess.run patched in another file", dict(tool(), **{"other.py": "import subprocess\nsubprocess.run = print\n"}))
        self.check("os.system patched in another file", dict(tool("    return os.system(command)\n"),
                                                            **{"other.py": "import os\nos.system = print\n"}))
        self.check("a local alias bound twice", tool("    go = subprocess.run\n    go = print\n    return go(command, shell=True)\n"))
        self.check("a module alias bound twice", tool("    return go(command, shell=True)\n",
                                                     module="go = subprocess.run\ngo = print\n"))
        for kw in ("executable='/bin/sh'", "env={'BASH_ENV': '/tmp/x'}", "preexec_fn=print", "input='x'", "shell=SHELL_FLAG"):
            self.check(f"subprocess.run with {kw}", tool(f"    return subprocess.run(command, shell=True, {kw}).returncode\n",
                                                        module="SHELL_FLAG = True\n"))
        with self.subTest(case="open with an opener"):
            self.assertNotEqual(score(tool("    return open(command, opener=print).read()\n"))[1]["G2"], "VERIFIED")
        self.check("subprocess.run with literal safe options",
                   tool("    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30).stdout\n"), want=8)

    def test_4_files_the_index_does_not_score_can_still_tamper(self):
        self.check("a test-named module patches the helper", dict(tool(), **{"test_setup.py": "import kit_guard\nkit_guard.refuses = len\n"}))
        self.check("a module under tests/ patches subprocess", dict(tool(), **{"tests/helpers.py": "import subprocess\nsubprocess.run = print\n"}))
        self.check("sitecustomize.py", dict(tool(), **{"sitecustomize.py": "x = 1\n"}))
        self.check("sitecustomize.py in a skipped folder", dict(tool(), **{"vendor/sitecustomize.py": "x = 1\n"}))
        self.check("a .pth file", dict(tool(), **{"lib/x.pth": "import os\n"}))


if __name__ == "__main__":
    unittest.main()
