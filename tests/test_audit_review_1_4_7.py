"""The independent review of 1.4.7 before packaging: inputs where the audit or the helper disagreed with the written
CANONICAL_FORMS or the helper's docstring. Each fixture is in tests/fixtures/review_1_4_7/ (see its README); the
shipped helper is written into a throwaway copy of each.
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import HELPER, ROOT, audit, guards, points
from test_audit_r6 import load_kit_guard

FIX = ROOT / "tests/fixtures/review_1_4_7"
EXPECT = {          # fixture -> G1-G3 points the written forms require
    "h1_set_add": 0, "h1_set_discard": 0, "h1_set_difference_update": 0, "h1_set_intersection_update": 0,
    "h1_set_symmetric_update": 0, "h1_from_import_set_add": 0,
    "h2_getattr_sys_path": 0, "h2_getattr_dict_update": 0, "h2_getattr_all_append": 0,
    "h3_getattr_client_options": 0, "h3_other_file_getattr_client_options": 0, "h4_getattr_module_opts": 0,
    "gap_returned_named_options": 0, "gap_returned_inline_options": 0,
    "l1_item_of_argv": 8, "l2_for_over_attribute": 8, "l3_own_folder_in_a_name": 8,
    "positive_returned_options_passed_whole": 8,
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


class Review147(unittest.TestCase):
    def test_every_fixture_scores_what_the_written_forms_say(self):
        self.assertEqual(sorted(EXPECT), sorted(p.name for p in FIX.iterdir() if p.is_dir()))
        for name, want in EXPECT.items():
            with self.subTest(fixture=name):
                pts, st = fixture_points(name)
                self.assertEqual(pts, want, st)

    def test_the_helper_refuses_what_its_braces_expand_to(self):
        kg = load_kit_guard()
        for v in ("cat x{1,2}{1,2}{1,2}{1,2}{1,2}/.{e,x}nv", "cat x{1,2}{1,2}{1,2}{1,2}{1,2}/{.e,x}nv",
                  "cat {a,b}{a,b}{a,b}{a,b}{a,b}/.ss{h,x}/config", "cat {a,b,c,d,e,f,g,h,.e}{nv,1,2,3,4,5,6,7}",
                  "cat .{d..f}nv", "cat .e{m..o}v", "cat id_{q..s}sa", "git --config-env alias.p=E p"):
            with self.subTest(value=v):
                self.assertTrue(kg.refuses(v))
        for v in ("echo {a..c}", "ls src/{a,b}.txt", "cat README.{md,txt}"):
            with self.subTest(control=v):
                self.assertFalse(kg.refuses(v))


if __name__ == "__main__":
    unittest.main()
