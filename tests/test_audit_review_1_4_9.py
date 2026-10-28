"""The independent review of 1.4.9 before packaging, kept as fixtures (tests/fixtures/review_1_4_9/, see its README).
Each case scores what the written CANONICAL_FORMS imply: 0 where they withhold credit, UNRESOLVED (no points, no
guard check MISSING) where the audit cannot read the hooks, 8 for the ordinary-code controls."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from test_audit_fairness import HELPER, ROOT, load_audit

FIX = ROOT / "tests/fixtures/review_1_4_9"
AUDIT = load_audit("audit_review_1_4_9")
GUARD = ("G1", "G2", "G3")


class Review149(unittest.TestCase):
    def test_every_case_scores_what_the_written_forms_imply(self):
        for label, e in sorted(json.loads((FIX / "expected.json").read_text()).items()):
            d = Path(tempfile.mkdtemp())
            try:
                shutil.copytree(FIX / label, d, dirs_exist_ok=True)
                (d / "kit_guard.py").write_text(HELPER)
                rep = AUDIT.audit(d)
                g = {c["id"]: c for c in rep.checks if c["id"] in GUARD}
                pts = sum(c["weight"] for c in g.values() if c["status"] == "VERIFIED")
                with self.subTest(case=label, finding=e["finding"]):
                    if e["want"] == "UNRESOLVED":
                        self.assertEqual(pts, 0, g)
                        self.assertNotIn("MISSING", {c["status"] for c in g.values()}, g)
                    else:
                        self.assertEqual(pts, e["want"], {k: (c["status"], c["evidence"][:200]) for k, c in g.items()})
            finally:
                shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
