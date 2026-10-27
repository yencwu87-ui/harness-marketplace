#!/usr/bin/env python3
"""Copy the single-source tools into the plugin templates and the kit. `--check` fails if any copy drifted (CI)."""
import filecmp
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COPIES = {
    "tools/harness.py": ["plugins/harness-init/skills/init/templates/harness.py", "kit/shared/scripts/harness.py"],
    "tools/redteam_live": ["plugins/harness-redteam/skills/redteam/templates/live", "kit/testing/live"],
    "kit/shared/kit_guard.py": ["kit/tracks/claude-agent-sdk/kit_guard.py"],
}


def files(src: Path):
    return [src] if src.is_file() else sorted(p for p in src.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def main():
    check = "--check" in sys.argv
    drift = []
    for src, dests in COPIES.items():
        s = ROOT / src
        for d in dests:
            dd = ROOT / d
            for f in files(s):
                target = dd if s.is_file() else dd / f.relative_to(s)
                if check:
                    if not target.exists() or not filecmp.cmp(f, target, shallow=False):
                        drift.append(str(target.relative_to(ROOT)))
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(f, target)
    if check:
        print("copies in sync" if not drift else "drifted: " + ", ".join(drift))
        sys.exit(1 if drift else 0)
    print("synced")


if __name__ == "__main__":
    main()
