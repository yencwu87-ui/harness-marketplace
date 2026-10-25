"""Tests for tools/harness.py: approve -> verify -> check, and every way the binding should break."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HARNESS = Path(__file__).resolve().parents[1] / "tools" / "harness.py"


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.r = Path(tempfile.mkdtemp())
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "Tester")
        (self.r / "progress").mkdir()
        (self.r / ".gitignore").write_text("__pycache__/\n")
        (self.r / "app.py").write_text("def add(a, b):\n    return a + b\n")
        (self.r / "test_app.py").write_text("from app import add\nassert add(2, 2) == 4\nprint('ok')\n")
        self.write_work([{
            "id": "F-001", "title": "add works",
            "done_when": [{"id": "c1", "run": f"{sys.executable} test_app.py"},
                          {"id": "h1", "human": "Owner confirms the function name"}],
            "passes": False, "evidence": "", "next_action": ""}])
        self.h("init")
        self.commit("start")

    def tearDown(self):
        shutil.rmtree(self.r)

    # helpers
    def git(self, *a):
        return subprocess.run(["git", *a], cwd=self.r, capture_output=True, text=True, check=True).stdout

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-qm", msg)

    def h(self, *a, ok=True):
        p = subprocess.run([sys.executable, str(HARNESS), *a], cwd=self.r, capture_output=True, text=True)
        if ok is not None:
            self.assertEqual(p.returncode == 0, ok, p.stdout + p.stderr)
        return p.stdout + p.stderr

    def write_work(self, items):
        (self.r / "progress" / "feature_list.json").write_text(json.dumps({"items": items}, indent=2))

    def work(self):
        return json.loads((self.r / "progress" / "feature_list.json").read_text())["items"]

    def full_pass(self):
        self.h("approve", "F-001", "--by", "Owner")
        self.h("signoff", "F-001", "h1", "--by", "Owner")
        self.commit("approve")
        self.h("verify", "F-001")
        self.commit("evidence")

    # tests
    def test_full_cycle_verifies(self):
        self.full_pass()
        self.assertTrue(self.work()[0]["passes"])
        out = self.h("check")
        self.assertIn("VERIFIED", out)

    def test_unapproved_item_cannot_be_verified_and_fails_check(self):
        self.h("verify", "F-001", ok=False)
        out = self.h("check", ok=True)  # not passing yet -> UNRESOLVED is fine
        self.assertIn("never approved", out)
        items = self.work(); items[0]["passes"] = True; self.write_work(items)
        self.h("check", ok=False)

    def test_hand_set_pass_without_evidence_fails(self):
        self.h("approve", "F-001", "--by", "Owner")
        items = self.work(); items[0]["passes"] = True; items[0]["evidence"] = "trust me"; self.write_work(items)
        out = self.h("check", ok=False)
        self.assertIn("no evidence", out)

    def test_checks_writing_files_are_reported(self):
        (self.r / ".gitignore").write_text("")
        self.commit("no ignore")
        self.h("approve", "F-001", "--by", "Owner")
        self.h("signoff", "F-001", "h1", "--by", "Owner")
        self.commit("approve")
        out = self.h("verify", "F-001")
        self.assertIn("wrote files", out)

    def test_criteria_change_after_approval_fails(self):
        self.full_pass()
        items = self.work(); items[0]["done_when"][0]["run"] = "true"; self.write_work(items)
        out = self.h("check", ok=False)
        self.assertIn("criteria changed since approval", out)

    def test_code_change_makes_evidence_stale(self):
        self.full_pass()
        (self.r / "app.py").write_text("def add(a, b):\n    return a + b  # edited\n")
        self.commit("edit code")
        out = self.h("check", ok=False)
        self.assertIn("stale", out)
        self.h("check", "--allow-stale", ok=True)

    def test_progress_edit_does_not_make_evidence_stale(self):
        self.full_pass()
        items = self.work(); items[0]["next_action"] = "next thing"; self.write_work(items)
        self.commit("progress note")
        self.h("check", ok=True)

    def test_tampered_log_fails(self):
        self.full_pass()
        rec = self.work()[0]["evidence"]
        log = next((self.r / rec).parent.glob("c1.log"))
        log.write_text("ok (edited)\n")
        out = self.h("check", ok=False)
        self.assertIn("altered", out)

    def test_edited_ledger_breaks_chain(self):
        self.full_pass()
        led = self.r / ".harness" / "ledger.jsonl"
        lines = led.read_text().splitlines()
        e = json.loads(lines[0]); e["by"] = "Someone else"; lines[0] = json.dumps(e)
        led.write_text("\n".join(lines) + "\n")
        out = self.h("check", ok=False)
        self.assertIn("ledger entry 1", out)

    def test_failing_check_does_not_pass(self):
        (self.r / "test_app.py").write_text("raise SystemExit(1)\n")
        self.commit("break test")
        self.h("approve", "F-001", "--by", "Owner")
        self.h("signoff", "F-001", "h1", "--by", "Owner")
        self.commit("approve")
        self.h("verify", "F-001", ok=False)
        self.assertFalse(self.work()[0]["passes"])
        self.assertIn("c1", self.work()[0]["next_action"])

    def test_missing_signoff_does_not_pass(self):
        self.h("approve", "F-001", "--by", "Owner")
        self.commit("approve")
        self.h("verify", "F-001", ok=False)
        self.assertFalse(self.work()[0]["passes"])

    def test_dirty_tree_refused(self):
        self.h("approve", "F-001", "--by", "Owner")
        (self.r / "app.py").write_text("# uncommitted\n")
        out = self.h("verify", "F-001", ok=False)
        self.assertIn("dirty tree", out)

    def test_removed_item_needs_retire(self):
        self.full_pass()
        self.write_work([])
        out = self.h("check", ok=False)
        self.assertIn("harness retire", out)
        self.h("retire", "F-001", "--by", "Owner", "--reason", "descoped")
        self.h("check", ok=True)


if __name__ == "__main__":
    unittest.main()
