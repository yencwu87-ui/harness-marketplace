"""DeepTeam on the REAL tool path: each simulated attack runs through the live harness.

The callback returns the agent's text plus a plain account of its actions, so DeepTeam's judge sees behaviour,
and the deterministic detector results are written to results/deepteam-live-*.json for the actual verdict.
    python deepteam_live.py --repo ../../../.. --channel readme
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import redteam_live as rl  # noqa: E402

from deepteam import red_team
from deepteam.attacks.single_turn import PromptInjection
from deepteam.vulnerabilities import ExcessiveAgency, PromptLeakage, ShellInjection

RESULTS = []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="../../../..")
    ap.add_argument("--channel", default="readme")
    a = ap.parse_args()
    repo = Path(a.repo).resolve()
    cfg = rl.load_config(repo, None)
    ok, msg = rl.check_parity(repo, cfg)
    if not ok:
        sys.exit(f"parity: {msg}")
    channels = {c["id"]: c for c in json.loads((rl.HERE / "channels.json").read_text())["channels"]}

    async def callback(input: str, turns=None) -> str:
        r = rl.run_attack(repo, cfg, {"id": f"deepteam-{len(RESULTS) + 1}", "channel": a.channel, "text": input}, channels)
        RESULTS.append(r)
        actions = "; ".join(f"{v['detector']}: {v['evidence']}" for v in r["violations"]) or "no forbidden actions observed"
        return f"{r.get('stdout_tail', '')}\n\n[observed actions] {actions}"

    from deepeval.models import AnthropicModel
    judge = AnthropicModel(model="claude-sonnet-5-5")
    red_team(model_callback=callback, simulator_model=judge, evaluation_model=judge,
             vulnerabilities=[PromptLeakage(types=["secrets_and_credentials"]), ExcessiveAgency(types=["permissions", "autonomy"]), ShellInjection()],
             attacks=[PromptInjection()], attacks_per_vulnerability_type=1, target_purpose="engineering agent in a code repository")
    out = Path(__file__).parent / "results"
    out.mkdir(exist_ok=True)
    path = out / f"deepteam-live-{time.strftime('%Y%m%d-%H%M')}.json"
    path.write_text(json.dumps(RESULTS, indent=2))
    bad = sum(1 for r in RESULTS if r["verdict"] == "INCORRECT")
    print(f"Deterministic verdict: {bad} of {len(RESULTS)} attacks produced forbidden actions. Details: {path}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
