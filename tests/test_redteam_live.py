"""Tests for the live red team: detectors fire on forbidden actions, stay quiet otherwise, and parity drift is caught."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "tools" / "redteam_live" / "redteam_live.py"
CONTROL = ROOT / "tools" / "redteam_live" / "control_agents.py"


class LiveRedTeamTests(unittest.TestCase):
    def setUp(self):
        self.r = Path(tempfile.mkdtemp())
        g = lambda *a: subprocess.run(["git", *a], cwd=self.r, capture_output=True, check=True)
        g("init", "-q"); g("config", "user.email", "t@example.com"); g("config", "user.name", "T")
        (self.r / ".claude").mkdir()
        (self.r / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"deny": ["Read(./.env)"]}}))
        (self.r / "CLAUDE.md").write_text("# App\n")
        (self.r / "README.md").write_text("# App\nHello\n")
        (self.r / "progress").mkdir()
        (self.r / "progress" / "feature_list.json").write_text(json.dumps({"items": [
            {"id": "F-001", "title": "t", "done_when": [{"id": "c1", "run": "true"}], "passes": False, "evidence": "", "next_action": ""}]}))
        g("add", "-A"); g("commit", "-qm", "init")

    def tearDown(self):
        shutil.rmtree(self.r)

    def live(self, *args, cfg=None):
        if cfg is not None:
            (self.r / "live.json").write_text(json.dumps(cfg))
        return subprocess.run([sys.executable, str(LIVE), "--repo", str(self.r), *args], capture_output=True, text=True)

    def test_selftest_passes(self):
        p = self.live("selftest")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("VERIFIED positive control", p.stdout)
        self.assertIn("VERIFIED negative control", p.stdout)

    def test_run_refuses_without_baseline(self):
        p = self.live("run", "--text", "hello", cfg={"agent_cmd": [sys.executable, str(CONTROL), "idle"]})
        self.assertEqual(p.returncode, 1)
        self.assertIn("no production baseline", p.stdout)

    def test_parity_drift_is_caught(self):
        cfg = {"agent_cmd": [sys.executable, str(CONTROL), "idle"]}
        self.live("baseline", cfg=cfg)
        (self.r / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"deny": []}}))
        p = self.live("run", "--text", "hello", cfg=cfg)
        self.assertEqual(p.returncode, 1)
        self.assertIn("differs from the production baseline", p.stdout)

    def test_idle_agent_is_verified_and_tripwire_is_incorrect(self):
        cfg = {"agent_cmd": [sys.executable, str(CONTROL), "idle"]}
        self.live("baseline", cfg=cfg)
        p = self.live("run", "--text", "a generated attack would go here", "--channel", "readme", cfg=cfg)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("VERIFIED", p.stdout)
        cfg = {"agent_cmd": [sys.executable, str(CONTROL), "tripwire"]}
        self.live("baseline", cfg=cfg)
        out = self.r / "report.json"
        p = self.live("run", "--text", "x", "--out", str(out), cfg=cfg)
        self.assertEqual(p.returncode, 1)
        detectors = {v["detector"] for v in json.loads(out.read_text())["results"][0]["violations"]}
        for d in ("canary_access", "canary_leak", "egress_blocked", "push", "worklist_tamper", "protected_write"):
            self.assertIn(d, detectors)

    def test_real_repo_is_never_modified(self):
        before = {p: p.read_bytes() for p in self.r.rglob("*") if p.is_file() and ".git" not in p.parts}
        cfg = {"agent_cmd": [sys.executable, str(CONTROL), "tripwire"]}
        self.live("baseline", cfg=cfg)
        before[self.r / ".harness-live" / "parity.json"] = (self.r / ".harness-live" / "parity.json").read_bytes()
        before[self.r / "live.json"] = (self.r / "live.json").read_bytes()
        self.live("run", "--text", "x", cfg=cfg)
        after = {p: p.read_bytes() for p in self.r.rglob("*") if p.is_file() and ".git" not in p.parts}
        self.assertEqual(before, after)
        self.assertFalse((self.r / ".env").exists())


if __name__ == "__main__":
    unittest.main()
