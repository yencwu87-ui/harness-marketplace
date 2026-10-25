"""Tests for the harness-audit script: scores, verdicts and exit codes."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "plugins/harness-audit/skills/audit/scripts/audit.py"
TEMPLATES = ROOT / "plugins/harness-init/skills/init/templates"


def run(repo, *args):
    p = subprocess.run([sys.executable, str(AUDIT), str(repo), *args], capture_output=True, text=True)
    return p.returncode, p.stdout


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_empty_repo_scores_zero_and_strict_fails(self):
        code, out = run(self.tmp, "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["score"], 0)
        code, _ = run(self.tmp, "--strict")
        self.assertEqual(code, 1)

    def test_scaffolded_repo_scores_well(self):
        r = self.tmp
        (r / "progress").mkdir()
        (r / "scripts").mkdir()
        (r / ".claude" / "agents").mkdir(parents=True)
        (r / "tests").mkdir()
        for f in ("feature_list.json", "progress.md", "clean-state.md"):
            shutil.copy(TEMPLATES / f, r / "progress" / f)
        shutil.copy(TEMPLATES / "DECISIONS.md", r)
        shutil.copy(TEMPLATES / "CLAUDE.md", r)
        shutil.copy(TEMPLATES / "init.sh", r)
        shutil.copy(TEMPLATES / "check_feature_list.py", r / "scripts")
        shutil.copy(TEMPLATES / ".claude" / "settings.json", r / ".claude")
        for a in (ROOT / "plugins/harness-core/agents").glob("*.md"):
            shutil.copy(a, r / ".claude" / "agents")
        (r / "tests" / "test_x.py").write_text("def test_x():\n    assert True\n")
        (r / "Makefile").write_text("check:\n\tpytest -q\n")
        (r / ".gitignore").write_text(".env\n.env.*\n")
        (r / ".git").mkdir()
        code, out = run(r, "--json")
        rep = json.loads(out)
        self.assertGreaterEqual(rep["score"], 80, [c for c in rep["checks"] if c["status"] != "VERIFIED"])
        verified = {c["id"] for c in rep["checks"] if c["status"] == "VERIFIED"}
        for cid in ("I1", "S1", "S2", "S4", "V4", "P2", "G1", "G2"):
            self.assertIn(cid, verified)

    def test_every_pass_has_evidence_and_every_gap_a_fix(self):
        _, out = run(ROOT, "--json")
        for c in json.loads(out)["checks"]:
            if c["status"] == "VERIFIED":
                self.assertTrue(c["evidence"], c["id"])
            else:
                self.assertTrue(c["fix"], c["id"])

    def test_long_instructions_are_unresolved_not_verified(self):
        (self.tmp / "CLAUDE.md").write_text("# P\n" + "line\n" * 300)
        _, out = run(self.tmp, "--json")
        i2 = next(c for c in json.loads(out)["checks"] if c["id"] == "I2")
        self.assertEqual(i2["status"], "UNRESOLVED")

    def test_pytest_fixture_is_not_a_verification_command(self):
        (self.tmp / "CLAUDE.md").write_text("# P\nUse @pytest.fixture(autouse=True) in tests.\n")
        _, out = run(self.tmp, "--json")
        i3 = next(c for c in json.loads(out)["checks"] if c["id"] == "I3")
        self.assertEqual(i3["status"], "MISSING")
        (self.tmp / "CLAUDE.md").write_text("# P\n- Full check: `make check`\n")
        _, out = run(self.tmp, "--json")
        i3 = next(c for c in json.loads(out)["checks"] if c["id"] == "I3")
        self.assertEqual(i3["status"], "VERIFIED")

    def test_min_threshold_sets_exit_code(self):
        code, _ = run(self.tmp, "--min", "10")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
