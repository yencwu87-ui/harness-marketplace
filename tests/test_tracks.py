"""Track checks: every kit track follows kit/tracks/TRACK_SPEC.md, and every full track's starter drives one
tool call offline (against tests/llm_stub.py on 127.0.0.1) with the call recorded to $HARNESS_TRACE.

The smoke tests run only when that framework is importable in the current Python, so plain CI skips them
cleanly. To run one: create the track's venv (make setup TRACK=<id>), then
  <venv>/bin/python -m unittest tests.test_tracks -v
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACKS = ROOT / "kit" / "tracks"
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "tools" / "redteam_live"))

PARSER_KEYS = {"claude_settings", "mcp_json", "env_example", "python_tool_list", "openai_agents_tools",
               "langgraph_tools", "crewai_tools", "strands_tools", "generic_declared"}
HOOK_KINDS = {"callback", "middleware", "event", "wrapper"}
FULL = {"claude-code", "claude-agent-sdk", "microsoft-agent-framework", "google-adk",
        "langgraph", "openai-agents-sdk", "crewai", "strands-agents"}
ASSESS_ONLY = {"llamaindex", "pydantic-ai", "smolagents", "haystack", "dspy", "agno", "mastra", "vercel-ai-sdk"}


def tracks() -> dict[str, dict]:
    return {p.parent.name: json.loads(p.read_text()) for p in sorted(TRACKS.glob("*/harness_track.json"))}


class TrackSpecTests(unittest.TestCase):
    def test_every_track_folder_has_a_spec_file_and_the_set_is_as_documented(self):
        folders = {p.name for p in TRACKS.iterdir() if p.is_dir()}
        self.assertEqual(folders, set(tracks()))
        self.assertEqual({k for k, v in tracks().items() if v["support"] == "full"}, FULL)
        self.assertEqual({k for k, v in tracks().items() if v["support"] == "assess-only"}, ASSESS_ONLY)

    def test_each_spec_has_the_required_shape(self):
        keys = {"schema", "id", "name", "language", "support", "framework", "entry", "tool_hook",
                "reach_sources", "detect", "notes"}
        for tid, d in tracks().items():
            with self.subTest(track=tid):
                self.assertEqual(set(d), keys)
                self.assertEqual(d["schema"], "harness-track/1")
                self.assertEqual(d["id"], tid)
                self.assertIn(d["language"], {"python", "typescript"})
                self.assertIn(d["support"], {"full", "assess-only"})
                self.assertTrue(d["framework"]["package"] and re.fullmatch(r"\d+\.\d+\.\d+.*", d["framework"]["version"]))
                self.assertTrue(d["reach_sources"])
                for r in d["reach_sources"]:
                    self.assertIn(r["kind"], PARSER_KEYS)
                    self.assertTrue(r["file"])
                self.assertTrue(d["detect"])
                for s in d["detect"]:
                    self.assertTrue(s["file"])
                    self.assertIsInstance(s["contains"], str)
                self.assertTrue((TRACKS / tid / "README.md").exists())
                self.assertNotIn("\n", d["notes"])

    def test_full_tracks_name_a_real_entry_and_hook_and_pin_their_framework(self):
        for tid, d in tracks().items():
            if d["support"] != "full":
                continue
            with self.subTest(track=tid):
                self.assertTrue((TRACKS / tid / d["entry"]).exists(), d["entry"])
                self.assertIn(d["tool_hook"]["kind"], HOOK_KINDS)
                f, sym = d["tool_hook"]["where"].rsplit(":", 1)
                src = (TRACKS / tid / f).resolve()
                self.assertTrue(src.exists(), f)
                if src.suffix == ".py":
                    text = src.read_text()
                    if tid == "claude-code":  # a hook script: the symbol is the hook event it serves
                        self.assertIn(sym, text)
                    else:
                        self.assertRegex(text, rf"(def|class) {re.escape(sym)}\b")
                    self.assertIn("HARNESS_TRACE", src.read_text())
                req = TRACKS / tid / "requirements.txt"
                if req.exists():
                    self.assertIn(d["framework"]["package"], req.read_text())
                    if tid not in {"claude-agent-sdk", "microsoft-agent-framework", "google-adk"}:  # pre-1.4 use >=
                        self.assertIn(f"=={d['framework']['version']}", req.read_text())

    def test_assess_only_tracks_ship_no_starter_and_say_so(self):
        for tid, d in tracks().items():
            if d["support"] != "assess-only":
                continue
            with self.subTest(track=tid):
                self.assertIsNone(d["entry"])
                self.assertIsNone(d["tool_hook"])
                self.assertEqual(sorted(p.name for p in (TRACKS / tid).iterdir()), ["README.md", "harness_track.json"])
                self.assertIn("Assess-only", (TRACKS / tid / "README.md").read_text())

    def test_target_and_makefile_list_every_full_code_track(self):
        target = (ROOT / "kit/shared/target.py").read_text()
        make = (ROOT / "kit/Makefile").read_text()
        for tid in FULL:
            self.assertIn(tid, make)
            if tid != "claude-code":
                self.assertIn(f'"{tid}"', target)
        for tid in ASSESS_ONLY:
            self.assertNotIn(f'"{tid}"', target)

    def test_choosing_and_readme_list_every_track(self):
        choosing = (ROOT / "kit/CHOOSING.md").read_text()
        for tid, d in tracks().items():
            self.assertIn(d["name"].split(" (")[0], choosing, tid)

    def test_redteam_live_presets_cover_the_full_tracks(self):
        import redteam_live as rl
        self.assertEqual(set(rl.TRACK_PRESETS), FULL)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "live.json").write_text(json.dumps({"track": "langgraph", "timeout": 5}))
            cfg = rl.load_config(Path(d), None)
            self.assertEqual(cfg["agent_cmd"][1:], ["harness/tracks/langgraph/agent.py", "--ask", "{task}"])
            self.assertFalse(cfg["install_trace_hook"])
            self.assertEqual(cfg["timeout"], 5)
            (Path(d) / "live.json").write_text(json.dumps({"track": "dspy"}))
            with self.assertRaises(SystemExit):
                rl.load_config(Path(d), None)


# ------------------------------------------------------------------ offline smoke tests
SMOKE = {  # track -> (module the framework installs, env var that points model calls at the stub)
    "langgraph": ("langgraph", "ANTHROPIC_BASE_URL"),
    "openai-agents-sdk": ("agents", "OPENAI_BASE_URL"),
    "crewai": ("crewai", "ANTHROPIC_BASE_URL"),
    "strands-agents": ("strands", "ANTHROPIC_BASE_URL"),
}


def _has(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


class TrackSmokeTests(unittest.TestCase):
    def _smoke(self, tid: str):
        mod, base_env = SMOKE[tid]
        if not _has(mod):
            self.skipTest(f"{mod} not installed in this Python (make setup TRACK={tid})")
        from llm_stub import Stub

        with Stub() as stub, tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "repo"
            (repo / "progress").mkdir(parents=True)
            (repo / "progress/feature_list.json").write_text(json.dumps(
                {"items": [{"id": "F-001", "passes": False, "done_when": []}]}))
            trace = Path(d) / "trace.jsonl"
            saved = dict(os.environ)
            os.environ.update({"HARNESS_TRACE": str(trace), "KIT_REPO": str(repo), base_env: stub.url,
                               "ANTHROPIC_API_KEY": "stub-not-a-key", "OPENAI_API_KEY": "stub-not-a-key"})
            try:
                entry = TRACKS / tid / tracks()[tid]["entry"]
                spec = importlib.util.spec_from_file_location(f"kit_track_smoke_{tid.replace('-', '_')}", entry)
                m = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(m)
                out = asyncio.run(m.ask("What is the next item?"))
            finally:
                os.environ.clear()
                os.environ.update(saved)
            self.assertIn("F-001", out)                       # the tool result reached the answer
            self.assertTrue(stub.calls, "no model call reached the local stub")
            lines = [json.loads(x) for x in trace.read_text().splitlines() if x.strip()]
            self.assertEqual([x["tool"] for x in lines], ["next_item"])
            self.assertEqual(set(lines[0]), {"ts", "source", "tool", "input"})

    def test_langgraph(self):
        self._smoke("langgraph")

    def test_openai_agents_sdk(self):
        self._smoke("openai-agents-sdk")

    def test_crewai(self):
        self._smoke("crewai")

    def test_strands_agents(self):
        self._smoke("strands-agents")


if __name__ == "__main__":
    unittest.main()
