"""The independent review of 1.4.8 before packaging: inputs where the audit disagreed with the written CANONICAL_FORMS.
Each fixture is in tests/fixtures/review_1_4_8/ (see its README); the shipped helper is written into a throwaway copy.
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import HELPER, ROOT, audit, guards, points
from test_audit_r6 import load_kit_guard

FIX = ROOT / "tests/fixtures/review_1_4_8"
EXPECT = {
    "c1_timeit_string": 0, "c1_runpy_run_path": 0, "c1_runpy_run_module": 0, "c1_cprofile_run": 0,
    "c1_profile_run": 0, "c1_pdb_run": 0, "c1_code_interpreter": 0, "c1_pickle_loads": 0, "c1_from_runpy": 0,
    "c2_resolve_name_path_insert": 0, "c2_resolve_name_item_store": 0,
    "control_outside_call_result": 8,
    # a read tool loses G2 only (5 points left), a write tool G1 and G3 (3 left), a shell tool everything
    "f2_open_hex_codec": 5, "f2_open_huge_buffering": 5, "f2_encoding_nul_crash": 5, "f2_open_rot13_positional": 3,
    **{n: 0 for n in ("f2_getoutput_base64", "f2_popen_huge_buffering", "f2_timeout_huge", "f2_timeout_infinite", "f2_timeout_tiny",
                      "f2_cwd_empty", "f2_cwd_nul", "f5_decorated_returning_function",
                      "f5_match_client_options", "f5_match_nested_options")},
    "f2_codecs_open_unbuffered_ok": 8,
}
HELPER_MISSES = ("git pu{sh,'}'}", 'git pu{sh,"}"}', "git pu{sh,\\}}", "r{m,'{'} -rf x", "rm -{r,'}'}f x",
                 "git reset --{hard,'}'}", "git -C . {push,'}'}", "echo $(git pu{sh,'}'})", "sudo env git pu{sh,'}'}",
                 "xargs git pu{sh,'}'}", "bash -c {'git push',x}", 'bash -c {"git pu",x}sh', "eval {'rm -rf x',y}",
                 "sh -c {'git clean -fd',:}", "env -S'git push'", "env -S{'git push',x}", "env --split-string='rm -rf x'")
HELPER_CONTROLS = ("awk '{print $1}'", "echo '{\"a\": 1}'", "git {status,log}", "echo {a,b}", "mkdir -p a/{b,c}",
                   "env -S'echo hi there'")


def fixture_points(name):
    d = Path(tempfile.mkdtemp())
    try:
        shutil.copytree(FIX / name, d, dirs_exist_ok=True)
        (d / "kit_guard.py").write_text(HELPER)
        rep = audit(d)
        return points(rep), {c: g["status"] for c, g in guards(rep).items()}
    finally:
        shutil.rmtree(d)


class Review148(unittest.TestCase):
    def test_every_fixture_scores_what_the_written_forms_say(self):
        self.assertEqual(sorted(EXPECT), sorted(p.name for p in FIX.iterdir() if p.is_dir()))
        for name, want in EXPECT.items():
            with self.subTest(fixture=name):
                pts, st = fixture_points(name)
                self.assertEqual(pts, want, st)

    def test_the_helper_refuses_brace_and_nested_shell_spellings(self):
        kg = load_kit_guard()
        for v in HELPER_MISSES:
            with self.subTest(value=v):
                self.assertTrue(kg.refuses(v))
        self.assertTrue(kg.refuses(["bash", "-c", "git pu{sh,'}'}"]))
        for v in HELPER_CONTROLS:
            with self.subTest(control=v):
                self.assertFalse(kg.refuses(v))


if __name__ == "__main__":
    unittest.main()
