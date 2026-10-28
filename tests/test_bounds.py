"""1.4.10: every recursion, depth, size, count or time bound in audit.py and kit_guard.py fails closed.

The table (also in DECISIONS.md and the fix report) lists each bound, the largest input it reads in full, and what
happens past it: in the audit UNRESOLVED or no credit, in the helper refused. Each bound is tested here at bound-1,
at the bound and at bound+1, with cycles where a cycle can reach it. Nothing here uses the network, a model or an
installed framework.
"""
import ast
import unittest

from test_audit_fairness import HELPER, Repo
from test_audit_r9 import AUDIT, KG

GUARD = ("G1", "G2", "G3")
HEAD = "import subprocess\nfrom pathlib import Path\nfrom agents import Agent\nfrom kit_guard import refuses\n"
GUARDED = ("def run(command):\n    if refuses(command):\n        return 'denied'\n"
           "    return subprocess.run(command, shell=True).returncode\n")
WIRE = "agent = Agent(name='w', tools=[run])\n"


def report(files):
    files = dict(files)
    files.setdefault("kit_guard.py", HELPER)
    with Repo(files) as d:
        rep = AUDIT.audit(d)
    return {c["id"]: c for c in rep.checks if c["id"] in GUARD}


def points(files):
    return sum(c["weight"] for c in report(files).values() if c["status"] == "VERIFIED")


class AuditBounds(unittest.TestCase):
    def assertRead(self, files, label):
        with self.subTest(case=label):
            self.assertEqual(points(files), 8, label)

    def assertStopped(self, files, label, bound_note=True):
        with self.subTest(case=label):
            g = report(files)
            self.assertEqual({c["status"] for c in g.values()}, {"UNRESOLVED"}, label)
            if bound_note:
                self.assertIn("stopped at a bound", " ".join(c["evidence"] for c in g.values()), label)

    # B1 MAX_FILES
    def test_files_walked(self):
        saved = AUDIT.MAX_FILES
        try:
            AUDIT.MAX_FILES = 12
            for n, read in ((10, True), (11, True), (12, True), (13, False), (20, False)):
                files = {"agent.py": HEAD + GUARDED + WIRE}
                files.update({f"pad/f{i:03}.txt": "x" for i in range(n - 2)})   # n files with kit_guard.py
                (self.assertRead if read else self.assertStopped)(files, f"{n} files, bound {AUDIT.MAX_FILES}")
        finally:
            AUDIT.MAX_FILES = saved

    # B2 MAX_FILE_BYTES
    def test_python_file_size(self):
        saved = AUDIT.MAX_FILE_BYTES
        try:
            AUDIT.MAX_FILE_BYTES = 60000                   # above the helper's own size
            for size, read in ((59999, True), (60000, True), (60001, False)):
                pad = "# " + "x" * (size - 3) + "\n"
                files = {"agent.py": HEAD + GUARDED + WIRE, "notes.py": pad}
                self.assertEqual(len(pad.encode()), size)
                (self.assertRead if read else self.assertStopped)(files, f"a {size}-byte file")
        finally:
            AUDIT.MAX_FILE_BYTES = saved

    # B3 a file the audit's parser does not read
    def test_unparsed_python_files(self):
        self.assertRead({"agent.py": HEAD + GUARDED + WIRE, "ok.py": "x = (1)\n"}, "parses")
        for label, text in (("syntax error", "def (:\n"), ("null byte", "x = 1\x00\n"),
                            ("nesting past the parser", "x = " + "(" * 400 + "1" + ")" * 400 + "\n")):
            self.assertStopped({"agent.py": HEAD + GUARDED + WIRE, "other.py": text}, label)

    # B4 MAX_RESOLVE_DEPTH (with an import cycle)
    def test_re_export_steps(self):
        def chain(hops):
            files = {"agent.py": "from agents import Agent\nfrom t1 import run\n" + WIRE}
            for i in range(1, hops):
                files[f"t{i}.py"] = f"from t{i + 1} import run\n"
            files[f"t{hops}.py"] = HEAD + GUARDED
            return files
        hops = AUDIT.MAX_RESOLVE_DEPTH // 2         # each hop is two resolve steps (the module, then the name)
        self.assertRead(chain(hops - 1), "one hop below the bound")
        self.assertRead(chain(hops), "at the bound")
        self.assertStopped(chain(hops + 1), "one hop past the bound", bound_note=False)   # nothing left VERIFIED
        cycle = {"agent.py": "from agents import Agent\nfrom t1 import run\n" + WIRE,
                 "t1.py": "from t2 import run\n", "t2.py": "from t1 import run\n"}
        self.assertStopped(cycle, "an import cycle", bound_note=False)

    # B5 tool-list value indirections (tool_reach, three)
    def test_tool_list_indirections(self):
        def tools(k):
            return {"agent.py": HEAD + GUARDED + "t0 = run\n" + "".join(f"t{i + 1} = t{i}\n" for i in range(k)) +
                    f"agent = Agent(name='w', tools=[t{k}])\n"}
        self.assertRead(tools(1), "two indirections")
        self.assertRead(tools(2), "three (the bound)")
        self.assertStopped(tools(3), "four", bound_note=False)     # UNRESOLVED by the existing rule

    # B6 function_reach depth (with recursion)
    def test_helper_call_depth(self):
        def helpers(n):
            hs = "".join(f"def h{i}():\n    return h{i + 1}()\n" for i in range(1, n)) + f"def h{n}():\n    return 1\n"
            return {"agent.py": HEAD + hs + "def run(command):\n    if refuses(command):\n        return 'denied'\n"
                    "    h1()\n    return subprocess.run(command, shell=True).returncode\n" + WIRE}
        self.assertRead(helpers(3), "three helpers deep")
        self.assertRead(helpers(4), "four (the bound)")
        self.assertStopped(helpers(5), "five", bound_note=False)
        rec = {"agent.py": HEAD + "def h1():\n    return h1()\n" + "def run(command):\n    if refuses(command):\n"
               "        return 'denied'\n    h1()\n    return subprocess.run(command, shell=True).returncode\n" + WIRE}
        self.assertStopped(rec, "a recursive helper", bound_note=False)

    # B7 MAX_PATH_STEPS
    def test_path_steps(self):
        def look(k, name):
            return {"agent.py": HEAD + f"def look(q):\n    return Path('{name}')" + ".resolve()" * k +
                    ".read_text()\nagent = Agent(name='w', tools=[look])\n"}
        b = AUDIT.MAX_PATH_STEPS
        for k in (b - 1, b):
            with self.subTest(k=k):
                self.assertEqual(points(look(k, "README.md")), 8)
                self.assertEqual(report(look(k, ".env"))["G2"]["status"], "MISSING")
        with self.subTest(k=b + 1):
            self.assertEqual(report(look(b + 1, ".env"))["G2"]["status"], "UNRESOLVED")
            self.assertEqual(report(look(b + 1, "README.md"))["G2"]["status"], "UNRESOLVED")

    def test_a_path_chain_the_audit_does_not_model_is_unresolved(self):
        for expr in ("Path('.').joinpath('.env').read_text()", "Path('a/b').parent.joinpath('.env').read_text()",
                     "Path('a.txt').with_name('.env').read_text()", "Path('.').joinpath('.env').open().read()"):
            files = {"agent.py": HEAD + f"def look(q):\n    return {expr}\nagent = Agent(name='w', tools=[look])\n"}
            with self.subTest(expr=expr):
                self.assertEqual(report(files)["G2"]["status"], "UNRESOLVED")

    # B8 _const_str / _str_list depth
    def test_constant_text_depth(self):
        def fixed(k):
            expr = "'us'"
            for _ in range(k):
                expr = f"('t' + {expr})"
            return {"agent.py": HEAD + f"def st(q):\n    return subprocess.run('git sta' + {expr}, shell=True).returncode\n"
                    "agent = Agent(name='w', tools=[st])\n"}
        self.assertRead(fixed(2), "nested 2")
        self.assertRead(fixed(3), "nested 3 (the bound)")
        self.assertStopped(fixed(4), "nested 4", bound_note=False)

    # B9 MAX_NAME_ALIASES (unit: past the bound the callee has no name)
    def test_local_alias_steps(self):
        mod = AUDIT.Module.__new__(AUDIT.Module)
        mod.alias = {"subprocess": "subprocess"}
        for k in (AUDIT.MAX_NAME_ALIASES - 1, AUDIT.MAX_NAME_ALIASES, AUDIT.MAX_NAME_ALIASES + 1):
            aliases = {"a0": ast.Name(id="subprocess")}
            aliases.update({f"a{i + 1}": ast.Name(id=f"a{i}") for i in range(k)})
            got = AUDIT._full_name(mod, aliases, ast.Attribute(value=ast.Name(id=f"a{k}"), attr="run"))
            with self.subTest(links=k):
                self.assertEqual(got, "subprocess.run" if k < AUDIT.MAX_NAME_ALIASES else "")

    # B10 MAX_ALIAS_STEPS (with a cycle)
    def test_alias_steps(self):
        def chain(steps):
            links = steps - 1
            return {"agent.py": HEAD + GUARDED + WIRE + "import patch\n",
                    "patch.py": "def f():\n    p0 = []\n" + "".join(f"    p{i + 1} = p{i}\n" for i in range(links)) +
                                f"    p{links}.append(1)\n"}
        b = AUDIT.MAX_ALIAS_STEPS
        self.assertRead(chain(b - 1), "one step below")
        self.assertRead(chain(b), "at the bound")
        self.assertStopped(chain(b + 1), "one past", bound_note=False)
        cycle = {"agent.py": HEAD + GUARDED + WIRE + "import patch\n",
                 "patch.py": "def f():\n    p = []\n    q = p\n    for _ in range(2):\n        p = q\n        q = p\n"
                             "    p.append(1)\n"}
        self.assertRead(cycle, "a cycle of safe aliases")

    # B11 a RecursionError anywhere in the code analysis
    def test_recursion_in_the_analysis(self):
        deep = "x = a" + ".b" * 3000 + "\n"
        try:
            ast.parse(deep)
        except (RecursionError, MemoryError, SyntaxError):
            self.skipTest("this Python's parser stops first (covered by B3)")
        files = {"agent.py": HEAD + GUARDED + WIRE + "import patch\n", "patch.py": deep}
        g = report(files)
        self.assertNotIn("VERIFIED", {c["status"] for c in g.values()})

    # B12 cycles in the class-object rule (Index.class_open, _class_closed) keep the non-cycle answer
    def test_class_cycles(self):
        two = ("class A:\n    def m(self):\n        B.m(self)\n        self.x = 1\n"
               "class B(A):\n    def m(self):\n        A.m(self)\n        self.y = 1\n")
        self.assertRead({"agent.py": HEAD + GUARDED + WIRE + "import patch\n", "patch.py": two}, "Base.m(self) both ways")

    # B13 MAX_TIMEOUT / MAX_BUFFERING: an option value past them is UNRESOLVED for that option
    def test_option_value_bounds(self):
        def timeout(v):
            return {"agent.py": HEAD + "def run(command):\n    if refuses(command):\n        return 'denied'\n"
                    f"    return subprocess.run(command, shell=True, timeout={v}).returncode\n" + WIRE}
        t = AUDIT.MAX_TIMEOUT
        self.assertRead(timeout(t - 1), "timeout below the bound")
        self.assertRead(timeout(t), "timeout at the bound")
        self.assertStopped(timeout(t + 1), "timeout past the bound", bound_note=False)


class HelperBounds(unittest.TestCase):
    """kit_guard: each bound read in full up to its value, refused past it (benign inputs, so a refusal is the bound)."""

    def test_nesting(self):
        def nest(depth):
            c = "echo hello world"
            for _ in range(depth):
                c = "sh -c '" + c.replace("'", "'\\''") + "'"
            return c
        b = KG._MAX_NESTING
        self.assertFalse(KG.refuses(nest(b - 1)))
        self.assertFalse(KG.refuses(nest(b)))
        self.assertTrue(KG.refuses(nest(b + 1)))
        self.assertTrue(KG.secret(nest(b + 1)))

    def test_brace_groups_and_expansions(self):
        self.assertFalse(KG.refuses("echo a{1,2}{3,4}{5,6}"))           # three groups
        self.assertFalse(KG.refuses("echo a{1,2}{3,4}{5,6}{7,8}"))      # four, the bound
        self.assertTrue(KG.refuses("echo a{1,2}{3,4}{5,6}{7,8}{9,0}"))  # five
        self.assertFalse(KG.refuses("echo {1..8}{1..7}"))               # 56 expansions
        self.assertFalse(KG.refuses("echo {1..8}{1..8}"))               # 64, the bound
        self.assertTrue(KG.refuses("echo {1..5}{1..13}"))               # 65

    def test_braced_words_and_readings(self):
        """In a shell string the whole string's 64-expansion bound comes first, so the readings bound is reached
        through an argument vector (each item is expanded on its own)."""
        self.assertFalse(KG.refuses("echo " + " ".join(["{a,b}"] * 3)))          # three braced words
        self.assertFalse(KG.refuses("echo " + " ".join(["{a,b}"] * 4)))          # four, the bound
        self.assertTrue(KG.refuses("echo " + " ".join(["{a,b}"] * 5)))           # five
        w = "{a,b,c}"                                                            # 4 readings each
        self.assertFalse(KG.refuses(["echo", w, w, "{a,b}", "{a,b}"]))           # 144 readings
        self.assertFalse(KG.refuses(["echo", w, w, w, w]))                       # 256, the bound
        self.assertTrue(KG.refuses(["echo", w, w, w, "{a,b,c,d}"]))              # 320

    def test_sequence_items(self):
        b = KG._MAX_SEQUENCE
        self.assertEqual(len(KG._sequence(f"1..{b - 1}")), b - 1)
        self.assertEqual(len(KG._sequence(f"1..{b}")), b)
        self.assertIs(KG._sequence(f"1..{b + 1}"), False)
        self.assertIsNone(KG._expand_braces("x{1.." + str(b + 1) + "}"))
        self.assertTrue(KG.refuses("echo {1..300}"))

    def test_glob_part_length(self):
        b = KG._MAX_GLOB
        self.assertFalse(KG.refuses("ls " + "a" * (b - 2) + "?"))
        self.assertFalse(KG.refuses("ls " + "a" * (b - 1) + "?"))
        self.assertTrue(KG.refuses("ls " + "a" * b + "?"))

    def test_percent_rounds(self):
        a = "A"
        enc = [a]
        for _ in range(KG._PERCENT_ROUNDS + 1):
            enc.append(enc[-1].replace("%", "%25") if "%" in enc[-1] else "%41")
        self.assertFalse(KG.refuses("echo " + enc[KG._PERCENT_ROUNDS - 1]))
        self.assertFalse(KG.refuses("echo " + enc[KG._PERCENT_ROUNDS]))
        self.assertTrue(KG.refuses("echo " + enc[KG._PERCENT_ROUNDS + 1]))
        self.assertTrue(KG.refuses("cat %25252e" + "env"))               # .env three times encoded: read and refused

    def test_container_depth(self):
        def nested(d):
            v = "ordinary"
            for _ in range(d):
                v = [v]
            return v
        b = KG._MAX_CONTAINERS
        self.assertFalse(KG.refuses(nested(b)))
        self.assertFalse(KG.refuses(nested(b + 1)))
        self.assertTrue(KG.refuses(nested(b + 2)))
        self.assertTrue(KG.refuses({"a": nested(b + 2)}))

    def test_recursion_error_is_refused(self):
        deep = "x"
        for _ in range(3000):
            deep = {"k": deep}
        self.assertTrue(KG.refuses(deep))


if __name__ == "__main__":
    unittest.main(verbosity=2)
