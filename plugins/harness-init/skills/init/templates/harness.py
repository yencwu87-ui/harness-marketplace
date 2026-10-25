#!/usr/bin/env python3
"""harness: bind each task's approved acceptance criteria to the exact evidence that satisfied them.

Standard library only. Run from the repository root.

    harness init                                  create .harness/ (ledger and evidence folders)
    harness approve ITEM --by NAME                a person approves the item's criteria (records criteria_sha)
    harness verify ITEM | --all                   the runner executes every machine check and records evidence
    harness signoff ITEM CHECK --by NAME [--note] a person confirms a human check, bound to the current criteria
    harness retire ITEM --by NAME --reason TEXT   remove an approved item on purpose
    harness check [--allow-stale]                 the guard: chain intact, criteria approved, passes backed by evidence
    harness status                                one line per item

Work list: progress/feature_list.json (or feature_list.json). Each item:
    {"id": "F-001", "title": "...", "done_when": [
        {"id": "c1", "run": "pytest -q tests/test_signup.py"},      machine check, run by `harness verify`
        {"id": "h1", "human": "Product owner confirms the wording"}  human check, needs `harness signoff`
     ], "passes": false, "evidence": "", "next_action": ""}
A plain string in done_when is treated as a human check.

Only `harness verify` may set passes to true. `harness check` fails when:
  - the ledger's hash chain is broken (history was edited);
  - an item's criteria (id, title, done_when) differ from its latest approval, or were never approved;
  - an item passes without an evidence record for its current criteria;
  - the evidence was recorded against different code (the code fingerprint excludes progress/ and .harness/);
  - an evidence record or log no longer matches the hash in the ledger;
  - a check failed, or a human check has no sign-off for the current criteria;
  - an approved item disappeared without `harness retire`.

Names given with --by are recorded as stated; tie them to real people with CODEOWNERS and required review on
progress/ and .harness/ in your Git host. CI should re-run `harness verify --all` on a clean runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.1.0"
GENESIS = "0" * 64
EXCLUDE = ("progress/", ".harness/", "feature_list.json")
ROOT = Path.cwd()


# ---------------------------------------------------------------- basics
def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def git(*args, check=True) -> str:
    p = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def excluded(path: str) -> bool:
    return any(path == e or path.startswith(e) for e in EXCLUDE)


def code_fingerprint() -> str:
    """Hash of the committed tree at HEAD, leaving out the progress and evidence files themselves."""
    lines = [l for l in git("ls-tree", "-r", "HEAD").splitlines() if not excluded(l.split("\t", 1)[1])]
    return sha("\n".join(lines))


def dirty_paths() -> list[str]:
    out = []
    for l in git("status", "--porcelain", "--untracked-files=all").splitlines():
        path = l[3:].split(" -> ")[-1].strip('"')
        if not excluded(path):
            out.append(path)
    return out


# ---------------------------------------------------------------- work list
def work_path() -> Path:
    for p in (ROOT / "progress" / "feature_list.json", ROOT / "feature_list.json"):
        if p.exists():
            return p
    raise SystemExit("No work list: expected progress/feature_list.json")


def load_work():
    p = work_path()
    data = json.loads(p.read_text(encoding="utf-8"))
    items = data["items"] if isinstance(data, dict) else data
    return p, data, items


def save_work(p: Path, data) -> None:
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def find(items, item_id):
    for it in items:
        if it.get("id") == item_id:
            return it
    raise SystemExit(f"No item {item_id} in the work list")


def checks_of(item) -> list[dict]:
    out = []
    for i, c in enumerate(item.get("done_when", []), 1):
        if isinstance(c, str):
            out.append({"id": f"h{i}", "human": c})
        elif isinstance(c, dict) and ("run" in c or "human" in c):
            out.append({"id": c.get("id", f"c{i}"), **{k: c[k] for k in ("run", "human") if k in c}})
        else:
            raise SystemExit(f"{item.get('id')}: done_when entry {i} needs 'run' or 'human'")
    ids = [c["id"] for c in out]
    if len(ids) != len(set(ids)):
        raise SystemExit(f"{item.get('id')}: duplicate check ids {ids}")
    return out


def criteria_sha(item) -> str:
    return sha(canon({"id": item.get("id"), "title": item.get("title"), "done_when": item.get("done_when", [])}))


# ---------------------------------------------------------------- ledger
def ledger_path() -> Path:
    return ROOT / ".harness" / "ledger.jsonl"


def read_ledger() -> list[dict]:
    p = ledger_path()
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def entry_hash(e: dict) -> str:
    return sha(canon({k: v for k, v in e.items() if k != "hash"}))


def append(entry: dict) -> dict:
    led = read_ledger()
    entry = {"seq": len(led) + 1, "ts": now(), **entry, "prev": led[-1]["hash"] if led else GENESIS}
    entry["hash"] = entry_hash(entry)
    ledger_path().parent.mkdir(parents=True, exist_ok=True)
    with open(ledger_path(), "a", encoding="utf-8") as f:
        f.write(canon(entry) + "\n")
    return entry


def chain_errors(led) -> list[str]:
    errs, prev = [], GENESIS
    for i, e in enumerate(led, 1):
        if e.get("prev") != prev:
            errs.append(f"ledger entry {i}: prev does not match entry {i - 1}'s hash (history edited or reordered)")
        if e.get("hash") != entry_hash(e):
            errs.append(f"ledger entry {i}: content does not match its hash (entry edited)")
        if e.get("seq") != i:
            errs.append(f"ledger entry {i}: seq is {e.get('seq')} (entry inserted or removed)")
        prev = e.get("hash")
    return errs


def latest(led, item_id, kind, **match):
    for e in reversed(led):
        if e.get("item") == item_id and e.get("type") == kind and all(e.get(k) == v for k, v in match.items()):
            return e
    return None


# ---------------------------------------------------------------- commands
def cmd_init(a):
    (ROOT / ".harness" / "evidence").mkdir(parents=True, exist_ok=True)
    ledger_path().touch()
    print("Created .harness/ (ledger.jsonl, evidence/). Commit it, and protect progress/ and .harness/ with CODEOWNERS.")


def cmd_approve(a):
    _, _, items = load_work()
    it = find(items, a.item)
    checks_of(it)
    e = append({"type": "approve", "item": a.item, "criteria_sha": criteria_sha(it), "by": a.by,
                "checks": [c["id"] for c in checks_of(it)]})
    print(f"Approved {a.item} by {a.by}: criteria {e['criteria_sha'][:12]} (ledger #{e['seq']})")


def cmd_signoff(a):
    _, _, items = load_work()
    it = find(items, a.item)
    cs = criteria_sha(it)
    if not latest(read_ledger(), a.item, "approve", criteria_sha=cs):
        raise SystemExit(f"{a.item}: current criteria are not approved; run `harness approve {a.item} --by NAME` first")
    chk = next((c for c in checks_of(it) if c["id"] == a.check), None)
    if not chk or "human" not in chk:
        raise SystemExit(f"{a.item}: {a.check} is not a human check")
    e = append({"type": "signoff", "item": a.item, "check": a.check, "criteria_sha": cs, "by": a.by, "note": a.note or ""})
    print(f"Signed off {a.item}/{a.check} by {a.by} (ledger #{e['seq']}). Run `harness verify {a.item}` to record evidence.")


def cmd_retire(a):
    e = append({"type": "retire", "item": a.item, "by": a.by, "reason": a.reason})
    print(f"Retired {a.item} by {a.by} (ledger #{e['seq']}). Remove it from the work list in the same commit.")


def verify_one(item_id: str, allow_dirty: bool, timeout: int) -> bool:
    p, data, items = load_work()
    it = find(items, item_id)
    cs, checks = criteria_sha(it), checks_of(it)
    led = read_ledger()
    if chain_errors(led):
        raise SystemExit("Ledger chain is broken; run `harness check` and fix that first.")
    if not latest(led, item_id, "approve", criteria_sha=cs):
        raise SystemExit(f"{item_id}: current criteria are not approved; a person must run `harness approve {item_id} --by NAME`")
    dirty = dirty_paths()
    if dirty and not allow_dirty:
        raise SystemExit(f"Refusing to verify on a dirty tree (commit or stash first): {', '.join(dirty[:5])}")
    started = time.time()
    run_dir = ROOT / ".harness" / "evidence" / item_id / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for c in checks:
        if "run" in c:
            t0 = time.time()
            try:
                pr = subprocess.run(c["run"], shell=True, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
                code, out = pr.returncode, (pr.stdout or "") + (pr.stderr or "")
            except subprocess.TimeoutExpired as ex:
                code, out = 124, f"TIMEOUT after {timeout}s\n{ex.stdout or ''}{ex.stderr or ''}"
            log = run_dir / f"{c['id']}.log"
            log.write_text(out, encoding="utf-8")
            results.append({"id": c["id"], "run": c["run"], "exit": code, "seconds": round(time.time() - t0, 2),
                            "log": log.relative_to(ROOT).as_posix(), "log_sha": sha(log.read_bytes())})
        else:
            so = latest(led, item_id, "signoff", criteria_sha=cs, check=c["id"])
            results.append({"id": c["id"], "human": c["human"], "signed_by": so["by"] if so else None,
                            "signoff_seq": so["seq"] if so else None})
    wrote = dirty_paths()
    if wrote and not dirty:
        print(f"Note: the checks wrote files outside progress/ and .harness/ ({', '.join(wrote[:5])}). "
              "Add them to .gitignore, or the next commit will change the code fingerprint and make this evidence stale.")
    ok = all(r.get("exit") == 0 for r in results if "run" in r) and all(r.get("signed_by") for r in results if "human" in r)
    record = {"item": item_id, "criteria_sha": cs, "code_sha": code_fingerprint(), "head": git("rev-parse", "HEAD").strip(),
              "dirty": bool(dirty), "checks": results, "all_passed": ok, "started": started, "seconds": round(time.time() - started, 2),
              "env": {"harness": VERSION, "python": platform.python_version(), "platform": platform.platform(),
                      "git": git("--version").strip()}}
    rec = run_dir / "evidence.json"
    rec.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    e = append({"type": "evidence", "item": item_id, "criteria_sha": cs, "code_sha": record["code_sha"], "dirty": bool(dirty),
                "record": rec.relative_to(ROOT).as_posix(), "record_sha": sha(rec.read_bytes()), "all_passed": ok})
    failed = [r["id"] for r in results if ("run" in r and r["exit"] != 0) or ("human" in r and not r["signed_by"])]
    it["passes"] = ok and not dirty
    it["evidence"] = rec.relative_to(ROOT).as_posix()
    if failed:
        it["next_action"] = f"Fix or sign off: {', '.join(failed)}"
    save_work(p, data)
    verdict = "VERIFIED" if it["passes"] else "INCORRECT"
    print(f"{verdict} {item_id}: {sum(1 for r in results if r.get('exit') == 0 or r.get('signed_by'))}/{len(results)} checks satisfied"
          f"{' (dirty tree: not counted)' if dirty else ''}; evidence {it['evidence']} (ledger #{e['seq']})")
    return it["passes"]


def cmd_verify(a):
    _, _, items = load_work()
    ids = [i["id"] for i in items] if a.all else [a.item]
    results = [verify_one(i, a.allow_dirty, a.timeout) for i in ids]
    sys.exit(0 if all(results) else 1)


def check_all(allow_stale=False) -> tuple[list, list]:
    """Return (rows, errors). rows: (item, verdict, message)."""
    _, _, items = load_work()
    led = read_ledger()
    rows, errs = [], chain_errors(led)
    current_code = code_fingerprint()
    present = {i.get("id") for i in items}
    for e in led:
        if e.get("type") == "approve" and e["item"] not in present and not latest(led, e["item"], "retire"):
            errs.append(f"{e['item']}: approved but missing from the work list (use `harness retire`)")
    for it in items:
        iid, cs = it.get("id"), criteria_sha(it)
        try:
            checks = checks_of(it)
        except SystemExit as ex:
            rows.append((iid, "INCORRECT", str(ex))); continue
        appr = latest(led, iid, "approve")
        # Unapproved or changed criteria block a pass, but an item that isn't passing can wait for approval.
        sev = "INCORRECT" if it.get("passes") else "UNRESOLVED"
        if not appr:
            rows.append((iid, sev, "criteria never approved (a person runs `harness approve`)")); continue
        if appr["criteria_sha"] != cs:
            rows.append((iid, sev, f"criteria changed since approval #{appr['seq']} by {appr['by']} "
                                   f"({appr['criteria_sha'][:12]} → {cs[:12]}); needs re-approval")); continue
        ev = latest(led, iid, "evidence", criteria_sha=cs)
        if not it.get("passes"):
            rows.append((iid, "UNRESOLVED", "not passing yet" + (f"; last evidence #{ev['seq']} failed" if ev else ""))); continue
        if not ev:
            rows.append((iid, "INCORRECT", "passes is true but no evidence was recorded for the current criteria")); continue
        if not ev.get("all_passed") or ev.get("dirty"):
            rows.append((iid, "INCORRECT", f"passes is true but evidence #{ev['seq']} {'was on a dirty tree' if ev.get('dirty') else 'has failing checks'}")); continue
        rec_p = ROOT / ev["record"]
        if not rec_p.exists() or sha(rec_p.read_bytes()) != ev["record_sha"]:
            rows.append((iid, "INCORRECT", f"evidence record {ev['record']} is missing or altered")); continue
        rec = json.loads(rec_p.read_text(encoding="utf-8"))
        bad_logs = [r["log"] for r in rec["checks"] if "log" in r and (not (ROOT / r["log"]).exists() or sha((ROOT / r["log"]).read_bytes()) != r["log_sha"])]
        if bad_logs:
            rows.append((iid, "INCORRECT", f"logs missing or altered: {', '.join(bad_logs)}")); continue
        if {c["id"] for c in checks} != {r["id"] for r in rec["checks"]}:
            rows.append((iid, "INCORRECT", "evidence does not cover every check")); continue
        if it.get("evidence") != ev["record"]:
            rows.append((iid, "INCORRECT", f"evidence field points at {it.get('evidence')!r}, ledger says {ev['record']}")); continue
        if ev["code_sha"] != current_code:
            if allow_stale:
                rows.append((iid, "UNRESOLVED", f"evidence #{ev['seq']} predates code changes; re-run `harness verify {iid}`")); continue
            rows.append((iid, "INCORRECT", f"stale: code changed since evidence #{ev['seq']}; re-run `harness verify {iid}`")); continue
        rows.append((iid, "VERIFIED", f"evidence #{ev['seq']} ({ev['record']}), {len(checks)} checks, code {current_code[:12]}"))
    return rows, errs


def cmd_check(a):
    rows, errs = check_all(a.allow_stale)
    for e in errs:
        print(f"INCORRECT ledger: {e}")
    for iid, v, msg in rows:
        print(f"{v:<10} {iid}: {msg}")
    bad = errs or any(v == "INCORRECT" for _, v, _ in rows)
    print(f"\nharness check {'FAILED' if bad else 'OK'}: {sum(v == 'VERIFIED' for _, v, _ in rows)} verified, "
          f"{sum(v == 'UNRESOLVED' for _, v, _ in rows)} unresolved, {sum(v == 'INCORRECT' for _, v, _ in rows)} incorrect")
    sys.exit(1 if bad else 0)


def cmd_status(a):
    rows, errs = check_all(allow_stale=True)
    if errs:
        print("Ledger problems:", *errs, sep="\n  ")
    for iid, v, msg in rows:
        print(f"{iid:<10} {v:<10} {msg}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="harness", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version=f"harness {VERSION}")
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("init").set_defaults(f=cmd_init)
    p = sp.add_parser("approve"); p.add_argument("item"); p.add_argument("--by", required=True); p.set_defaults(f=cmd_approve)
    p = sp.add_parser("signoff"); p.add_argument("item"); p.add_argument("check"); p.add_argument("--by", required=True)
    p.add_argument("--note"); p.set_defaults(f=cmd_signoff)
    p = sp.add_parser("retire"); p.add_argument("item"); p.add_argument("--by", required=True); p.add_argument("--reason", required=True)
    p.set_defaults(f=cmd_retire)
    p = sp.add_parser("verify"); g = p.add_mutually_exclusive_group(required=True); g.add_argument("item", nargs="?")
    g.add_argument("--all", action="store_true"); p.add_argument("--allow-dirty", action="store_true")
    p.add_argument("--timeout", type=int, default=900); p.set_defaults(f=cmd_verify)
    p = sp.add_parser("check"); p.add_argument("--allow-stale", action="store_true"); p.set_defaults(f=cmd_check)
    sp.add_parser("status").set_defaults(f=cmd_status)
    a = ap.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    main()
