#!/usr/bin/env python3
"""Fail if progress/feature_list.json changed anything other than passes, evidence, next_action.

Compares the working copy with the last commit (or with --base <ref>).
Use as a pre-commit hook or in CI:  python3 scripts/check_feature_list.py
Exit codes: 0 ok, 1 forbidden change, 2 file missing or invalid.
"""
import argparse
import json
import subprocess
import sys

PATH = "progress/feature_list.json"
AGENT_FIELDS = {"passes", "evidence", "next_action"}
REQUIRED = {"id", "title", "done_when", "passes"}


def load_base(ref):
    try:
        out = subprocess.run(["git", "show", f"{ref}:{PATH}"], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None  # first commit of the file, or not a git repo
    return json.loads(out.stdout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="HEAD")
    ap.add_argument("--file", default=PATH)
    args = ap.parse_args()

    try:
        with open(args.file, encoding="utf-8") as f:
            cur = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read {args.file}: {e}")
        return 2

    errors = []
    items = cur.get("items")
    if not isinstance(items, list):
        print("ERROR: top-level 'items' list missing")
        return 2
    ids = [i.get("id") for i in items]
    if len(ids) != len(set(ids)):
        errors.append("duplicate item ids")
    for i in items:
        missing = REQUIRED - i.keys()
        if missing:
            errors.append(f"{i.get('id', '?')}: missing {sorted(missing)}")
        if i.get("passes") is True and not str(i.get("evidence", "")).strip():
            errors.append(f"{i.get('id')}: passes is true but evidence is empty")

    base = load_base(args.base) if args.file == PATH else None
    if base is not None:
        b_items = base.get("items", [])
        if [x.get("id") for x in b_items] != ids:
            errors.append("items were added, removed or reordered (humans only)")
        for b, c in zip(b_items, items):
            if b.get("id") != c.get("id"):
                continue
            for k in (b.keys() | c.keys()) - AGENT_FIELDS:
                if b.get(k) != c.get(k):
                    errors.append(f"{c.get('id')}: field '{k}' changed (only passes/evidence/next_action may change)")
        for k in (base.keys() | cur.keys()) - {"items"}:
            if base.get(k) != cur.get(k):
                errors.append(f"top-level field '{k}' changed")

    if errors:
        print("feature_list check FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    done = sum(1 for i in items if i.get("passes") is True)
    print(f"feature_list check OK: {done}/{len(items)} passing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
