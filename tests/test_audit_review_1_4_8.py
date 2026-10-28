"""The independent review of 1.4.8 before packaging: inputs where the audit disagreed with the written CANONICAL_FORMS.
Each fixture is in tests/fixtures/review_1_4_8/ (see its README); the shipped helper is written into a throwaway copy.
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import HELPER, ROOT, audit, guards, points

FIX = ROOT / "tests/fixtures/review_1_4_8"
EXPECT = {
    "c1_timeit_string": 0, "c1_runpy_run_path": 0, "c1_runpy_run_module": 0, "c1_cprofile_run": 0,
    "c1_profile_run": 0, "c1_pdb_run": 0, "c1_code_interpreter": 0, "c1_pickle_loads": 0, "c1_from_runpy": 0,
    "c2_resolve_name_path_insert": 0, "c2_resolve_name_item_store": 0,
    "control_outside_call_result": 8,
}


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


if __name__ == "__main__":
    unittest.main()
