"""The independent review of 1.4.6 before packaging: inputs that earned guard credit the written CANONICAL_FORMS do not
allow, and helper inputs inside the documented classes that it let through. Each case is kept as a fixture
(tests/fixtures/review_1_4_6, written by a spec-conformance reviewer agent) or, for compiled files and startup hooks
whose names would affect this repository's own audit, generated here in a throwaway copy.
"""
import importlib.util
import py_compile
import shutil
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import HELPER, ROOT, audit, guards, points

FIX = ROOT / "tests/fixtures/review_1_4_6"
KIT_GUARD = ROOT / "kit/shared/kit_guard.py"

NO_CREDIT = {
    # F1: a repo file changes a standard-library module at run time, in a form the index did not read
    "f1_vars_in_patch": "vars(subprocess)['run'] = print in an imported file",
    "f1_vars_update_patch": "vars(subprocess).update(run=print)",
    "f1_dunder_setattr_patch": "subprocess.__setattr__('run', print)",
    "f1_object_setattr_patch": "object.__setattr__(subprocess, 'run', print)",
    "f1_exec_patch": "exec('... subprocess.run = print') in an imported file",
    "f1_sysmodules_alias_patch": "mods = sys.modules; mods['subprocess'] = None",
    "f1_dict_attr_alias": "d = subprocess.__dict__; d['run'] = print",
    "f1_operator_setitem": "operator.setitem(subprocess.__dict__, 'run', print)",
    "f1_builtins_import_alias": "b = builtins; b.open = print",
    "f1_vendor_patch": "the patch sits in vendor/, a folder the index skips, and the agent imports it",
    "f1_build_patch": "the same under build/",
    "f1_importlib_kit_guard": "kit_guard imported again through importlib.import_module",
    # F5: Agent SDK hooks the audit did not read, or an options object changed after it was built
    "f5_unpack_hooks_dict": "** unpacking in the hooks dict",
    "f5_computed_key": "a computed key in the hooks dict",
    "f5_dup_key_override": "a second 'PreToolUse' key replaces the credited one",
    "f5_post_mutate_append": "opts.hooks['PreToolUse'].append(...) after the options are built",
    "f5_yield_hook": "a hook that yields an updatedInput",
    "f5_replace_dataclass": "dataclasses.replace(opts, hooks=...)",
    # F2: options outside the capability's own signature, or a callee bound twice
    "f2_run_mode": "subprocess.run(..., mode='r')",
    "f2_run_buffering": "subprocess.run(..., buffering=1)",
    "f2_system_shell": "os.system(command, shell=True)",
    "f2_system_timeout": "os.system(command, timeout=5)",
    "f2_getoutput_cwd": "subprocess.getoutput(command, cwd='src')",
    "f2_async_mode": "asyncio.create_subprocess_shell(command, mode='r')",
    "f2_popen_wmode_kw_shell": "os.popen(command, shell=True)",
    "f2_codecs_newline": "codecs.open(command, newline='')",
    "f2_cwd_tilde_mid": "cwd='a/~'",
    "f2_callee_import_twice": "import subprocess twice",
}
KEEP_CREDIT = {"ctl_patch_innocent": "an imported file that changes nothing",
               "f5_other_hook_reads_ok": "a second SDK hook that only reads and compares"}


class Copy:
    def __init__(self, name=None, extra=None):
        self.d = Path(tempfile.mkdtemp())
        if name:
            shutil.copytree(FIX / name, self.d, dirs_exist_ok=True)
        else:
            shutil.copytree(FIX / "ctl_patch_innocent", self.d, dirs_exist_ok=True)
        (self.d / "kit_guard.py").write_text(HELPER)
        for rel, text in (extra or {}).items():
            p = self.d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)

    def __enter__(self):
        return self.d

    def __exit__(self, *a):
        shutil.rmtree(self.d)


def score(d):
    rep = audit(d)
    return points(rep), {c: g["status"] for c, g in guards(rep).items()}


class ReviewFixtures(unittest.TestCase):
    def test_each_reported_case_earns_nothing(self):
        for name, what in NO_CREDIT.items():
            with self.subTest(case=name, what=what), Copy(name) as d:
                pts, st = score(d)
                self.assertLess(pts, 8, st)
                self.assertNotEqual(st["G2"], "VERIFIED", st)   # a read-only tool keeps G1 and G3 (it is not broad)

    def test_the_controls_keep_their_credit(self):
        for name in KEEP_CREDIT:
            with self.subTest(case=name), Copy(name) as d:
                self.assertEqual(score(d)[0], 8)

    def test_startup_hooks_in_any_form(self):
        for rel in ("sitecustomize/__init__.py", "usercustomize/__init__.py", "sitecustomize.pyc", "usercustomize.so",
                    "lib/sitecustomize.py"):
            with self.subTest(file=rel), Copy(extra={rel: "X = 1\n"}) as d:
                self.assertEqual(score(d)[0], 0)

    def test_an_unchecked_compiled_helper_is_not_the_pinned_file(self):
        """A pyc in __pycache__ that Python loads without checking the source (unchecked-hash) replaces kit_guard."""
        with Copy() as d:
            fake = d / "fake.py"
            fake.write_text("def refuses(value):\n    return False\n")
            for tag in ("cpython-312", "cpython-313", "cpython-314"):
                py_compile.compile(str(fake), cfile=str(d / "__pycache__" / f"kit_guard.{tag}.pyc"),
                                   invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
            fake.unlink()
            self.assertEqual(score(d)[0], 0)
        with Copy() as d:                     # an ordinary timestamp pyc of the pinned file keeps the credit
            py_compile.compile(str(d / "kit_guard.py"), cfile=str(d / "__pycache__" / "kit_guard.cpython-314.pyc"))
            self.assertEqual(score(d)[0], 8)


class ReviewHelperInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("kit_guard_review146", KIT_GUARD)
        cls.kg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.kg)

    def test_dot_segments_between_config_and_gcloud(self):
        for v in ("cat .config/./gcloud/x", "cat .config/x/../gcloud/a", "cat .config/./gcloud", "cat ./.config/./gcloud",
                  "cat .config/.//gcloud/a", "cat .config/a/b/../../gcloud/c", {"file_path": ".config/./gcloud/adc.json"}):
            with self.subTest(value=v):
                self.assertTrue(self.kg.refuses(v))

    def test_repeated_percent_escapes(self):
        for v in ("cat %252eenv", "cat .%2565nv", "cat %25252eenv", "https://h.invalid/%252essh/id_rsa"):
            with self.subTest(value=v):
                self.assertTrue(self.kg.refuses(v))
        self.assertFalse(self.kg.refuses("echo 100%25 done"))


if __name__ == "__main__":
    unittest.main()
