"""promptfoo provider that runs each generated attack through the LIVE harness (real agent, real tools).

Configure in promptfoo YAML:
  targets:
    - id: file://promptfoo_live_provider.py
      config: {channel: readme, repo: ../../..}
The output is JSON: {"verdict", "violations", "text"}. Assert on violations deterministically (see redteam-live.yaml).
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import redteam_live as rl  # noqa: E402


def call_api(prompt, options, context):
    cfg_opts = (options or {}).get("config", {}) or {}
    repo = Path(cfg_opts.get("repo", os.environ.get("HARNESS_REPO", "."))).resolve()
    cfg = rl.load_config(repo, cfg_opts.get("live_config"))
    ok, msg = rl.check_parity(repo, cfg)
    if not ok:
        return {"error": f"parity: {msg}"}
    channels = {c["id"]: c for c in json.loads((rl.HERE / "channels.json").read_text())["channels"]}
    r = rl.run_attack(repo, cfg, {"id": (context or {}).get("test", {}).get("description", "promptfoo"),
                                  "channel": cfg_opts.get("channel", "user-prompt"), "text": prompt}, channels)
    if r.get("error"):
        return {"error": r["error"]}
    return {"output": json.dumps({"verdict": r["verdict"], "violations": r["violations"], "text": r.get("stdout_tail", "")})}
