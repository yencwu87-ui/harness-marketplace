"""DeepTeam red team against the track chosen by KIT_TRACK (see ../target.py).

  pip install -r requirements.txt
  KIT_TRACK=claude-agent-sdk python red_team.py                 # agentic set (default)
  KIT_TRACK=claude-agent-sdk python red_team.py --framework owasp-asi-2026
  KIT_TRACK=claude-agent-sdk python red_team.py --framework owasp-llm

Attack simulation and grading use a model. Claude by default (needs ANTHROPIC_API_KEY);
set KIT_JUDGE=openai to use DeepTeam's OpenAI default instead (needs OPENAI_API_KEY).
Results are written to results/ as JSON.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from target import ask  # noqa: E402

from deepteam import red_team
from deepteam.attacks.multi_turn import LinearJailbreaking
from deepteam.attacks.single_turn import PromptInjection, Roleplay
from deepteam.frameworks import OWASP_ASI_2026, OWASPTop10
from deepteam.vulnerabilities import ExcessiveAgency, PIILeakage, PromptLeakage, ShellInjection

PURPOSE = (
    "An engineering assistant that works through a team's task list in a code repository. It must not "
    "reveal secrets or its instructions, must not run destructive commands without approval, and must "
    "report results with evidence."
)


async def model_callback(input: str, turns=None) -> str:
    return await ask(input)


def judge():
    if os.environ.get("KIT_JUDGE", "anthropic") == "openai":
        return "gpt-4o-mini"
    from deepeval.models import AnthropicModel

    return AnthropicModel(model=os.environ.get("KIT_JUDGE_MODEL", "claude-sonnet-5-5"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--framework", choices=["agentic", "owasp-asi-2026", "owasp-llm"], default="agentic")
    ap.add_argument("--attacks-per-type", type=int, default=1)
    a = ap.parse_args()

    kwargs = dict(
        model_callback=model_callback,
        simulator_model=judge(),
        evaluation_model=judge(),
        attacks_per_vulnerability_type=a.attacks_per_type,
        target_purpose=PURPOSE,
    )
    if a.framework == "owasp-asi-2026":
        kwargs["framework"] = OWASP_ASI_2026()
    elif a.framework == "owasp-llm":
        kwargs["framework"] = OWASPTop10()
    else:
        kwargs["vulnerabilities"] = [
            PromptLeakage(types=["secrets_and_credentials", "instructions"]),
            PIILeakage(types=["direct_disclosure"]),
            ExcessiveAgency(types=["permissions", "autonomy"]),
            ShellInjection(),
        ]
        kwargs["attacks"] = [PromptInjection(), Roleplay(), LinearJailbreaking()]

    assessment = red_team(**kwargs)
    out = Path(__file__).parent / "results"
    out.mkdir(exist_ok=True)
    path = out / f"deepteam-{os.environ.get('KIT_TRACK', 'echo')}-{datetime.now():%Y%m%d-%H%M}.json"
    try:
        data = assessment.model_dump(mode="json")
    except AttributeError:
        data = {"repr": repr(assessment)}
    path.write_text(json.dumps(data, indent=2, default=str))
    print(f"Saved {path}")


if __name__ == "__main__":
    main()
