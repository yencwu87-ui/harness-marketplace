#!/usr/bin/env python3
"""harness-audit: score a repository's agent harness and say exactly what to fix.

Zero dependencies (Python 3.9+ standard library). Read-only: it never writes into the repo it audits.

    python3 audit.py [REPO]            human-readable report
    python3 audit.py [REPO] --json     machine-readable (for CI or dashboards)
    python3 audit.py [REPO] --md       Markdown (paste into a PR or progress file)
    python3 audit.py [REPO] --strict   exit 1 if any CRITICAL check fails (default: exit 1 only if score < --min)

Seven areas. The first four follow the subsystems taught in WalkingLabs' "Learn Harness Engineering"
course (MIT, https://github.com/walkinglabs/learn-harness-engineering); the last three are what the
course leaves out and production teams get burned by: safety guardrails, evals and red teaming,
and cost and context hygiene.

Every check reports VERIFIED (with the file and line that proves it), MISSING (what to add), or
UNRESOLVED (found something, but it can't be confirmed from files alone), plus a one-line fix.
Checks are heuristics over files: a pass means the harness piece exists, not that it works.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

VERSION = "1.0.1"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target", "site-packages", "third_party", "vendor"}
MAX_FILES = 60000
MAX_FILE_BYTES = 400_000


@dataclass
class Check:
    id: str
    area: str
    title: str
    weight: int              # 3 = critical, 2 = important, 1 = nice to have
    status: str = "MISSING"  # VERIFIED | MISSING | UNRESOLVED
    evidence: str = ""
    fix: str = ""


@dataclass
class Report:
    repo: str
    version: str = VERSION
    score: int = 0
    grade: str = ""
    checks: list = field(default_factory=list)
    areas: dict = field(default_factory=dict)


class Repo:
    def __init__(self, root: Path):
        self.root = root
        self._files = None

    def files(self):
        """Walk the tree once (skipping vendored and build folders); every pattern match reuses this list."""
        if self._files is None:
            out = []
            for dp, dns, fns in os.walk(self.root):
                dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".") or d in (".claude", ".github", ".devcontainer")]
                out += [Path(dp) / f for f in fns]
                if len(out) > MAX_FILES:
                    break
            self._files = out
            self._rel = [p.relative_to(self.root).as_posix() for p in out]
        return self._files

    @staticmethod
    def _rx(pattern: str):
        out, i = "", 0
        while i < len(pattern):
            if pattern.startswith("**/", i):
                out += "(?:.*/)?"; i += 3
            elif pattern.startswith("**", i):
                out += ".*"; i += 2
            elif pattern[i] == "*":
                out += "[^/]*"; i += 1
            elif pattern[i] == "?":
                out += "[^/]"; i += 1
            else:
                out += re.escape(pattern[i]); i += 1
        return re.compile(out + "$")

    def rel(self, p: Path) -> str:
        return str(p.relative_to(self.root))

    def first(self, *names):
        for n in names:
            p = self.root / n
            if p.exists():
                return p
        return None

    def glob(self, *patterns):
        files = self.files()
        hits = []
        for pat in patterns:
            rx = self._rx(pat)
            hits += [f for f, rel in zip(files, self._rel) if rx.match(rel)]
        return list(dict.fromkeys(hits))

    def text(self, p: Path | None) -> str:
        if not p or not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
            return ""
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def grep(self, p: Path | None, pattern: str, flags=re.I):
        """Return 'path:line  snippet' for the first match, or ''."""
        t = self.text(p)
        rx = re.compile(pattern, flags)
        for i, line in enumerate(t.splitlines(), 1):
            if rx.search(line):
                return f"{self.rel(p)}:{i}  {line.strip()[:90]}"
        return ""

    def grep_any(self, paths, pattern, flags=re.I):
        for p in paths:
            hit = self.grep(p, pattern, flags)
            if hit:
                return hit
        return ""


def audit(root: Path) -> Report:
    r = Repo(root)
    checks: list[Check] = []

    def add(cid, area, title, weight, ok, evidence="", fix="", unresolved=False):
        c = Check(cid, area, title, weight, fix=fix)
        if ok:
            c.status, c.evidence = "VERIFIED", evidence
        elif unresolved:
            c.status, c.evidence = "UNRESOLVED", evidence
        checks.append(c)

    instr = r.first("CLAUDE.md", "AGENTS.md", ".claude/CLAUDE.md", "GEMINI.md", ".github/copilot-instructions.md")
    instr_t = r.text(instr)
    settings = [p for p in (r.first(".claude/settings.json"), r.first(".claude/settings.local.json")) if p]
    settings_t = "\n".join(r.text(p) for p in settings)
    makefile = r.first("Makefile", "justfile", "Taskfile.yml", "package.json")
    mk_t = r.text(makefile)
    work_list = r.first("progress/feature_list.json", "feature_list.json", "features.json", "docs/feature_list.json")
    progress = r.first("progress/progress.md", "PROGRESS.md", "claude-progress.md", "claude-progress.txt", "progress.md",
                       "session-handoff.md", "docs/PROGRESS.md", "HANDOFF.md")
    agents_dir = r.root / ".claude" / "agents"
    agent_files = list(agents_dir.glob("*.md")) if agents_dir.is_dir() else []
    instr_all = [p for p in (r.first("CLAUDE.md"), r.first("AGENTS.md"), r.first(".claude/CLAUDE.md")) if p]
    docs_for_rules = list(dict.fromkeys(instr_all + [p for p in [instr] if p] + r.glob(".claude/skills/*/SKILL.md") + r.glob("docs/*.md")
                       + [p for p in (r.first("session-handoff.md"), r.first("clean-state-checklist.md"), progress) if p]))

    # 1. Instructions -----------------------------------------------------------------------------
    A = "1 Instructions"
    add("I1", A, "Agent instructions file at the root (CLAUDE.md / AGENTS.md)", 3, bool(instr),
        r.rel(instr) if instr else "", "Create CLAUDE.md or AGENTS.md: what the system is, how to run and test it, hard rules.")
    lines = len(instr_t.splitlines())
    add("I2", A, "Instructions are short enough to load every session (≤ 200 lines)", 2, bool(instr) and lines <= 200,
        f"{r.rel(instr)}: {lines} lines" if instr else "",
        f"Trim to about 200 lines; move workflow detail into skills that load on demand." if instr else "Create the file first.",
        unresolved=bool(instr) and lines > 200)
    VCMD = r"(`[^`]*(?<![\w@])(make (check|test|verify)|pytest|python3? -m pytest|npm (run )?test|cargo test|go test|yarn test|pnpm test|\./init\.sh|tox|nox)\b[^`]*`|^\s*\$?\s*(make (check|test)|pytest|npm test|cargo test|go test|\./init\.sh)\b)"
    add("I3", A, "Instructions name the verification command", 3,
        bool(r.grep(instr, VCMD)), r.grep(instr, VCMD),
        "List the one command that proves the code works (e.g. `make check`).")
    add("I4", A, "Hard rules are stated (MUST / NEVER)", 2, bool(r.grep(instr, r"\b(must not|must|never|do not|forbidden)\b")),
        r.grep(instr, r"\b(must not|must|never|do not|forbidden)\b"), "Add a short 'Hard rules' list: secrets, destructive commands, scope.")

    # 2. State and continuity ---------------------------------------------------------------------
    A = "2 State and continuity"
    add("S1", A, "Machine-readable work list (feature_list.json or equivalent)", 3, bool(work_list),
        r.rel(work_list) if work_list else "", "Add progress/feature_list.json: one entry per item with id, title, done_when, passes.")
    wl = {}
    if work_list:
        try:
            wl = json.loads(r.text(work_list) or "{}")
        except json.JSONDecodeError:
            wl = None
    items = (next((wl[k] for k in ("items", "features", "tasks") if k in wl), None) if isinstance(wl, dict) else wl) if wl is not None else None
    items = items if isinstance(items, list) else []
    has_dw = bool(items) and all(isinstance(i, dict) and any(k in i for k in ("done_when", "acceptance", "acceptance_criteria", "criteria", "steps", "verification", "verify")) for i in items)
    add("S2", A, "Every work item says what 'done' means (done_when)", 3, has_dw,
        f"{r.rel(work_list)}: {len(items)} items, all with done_when" if has_dw else "",
        "Give each item a done_when someone could check without asking: tests, commands, observable behaviour.",
        unresolved=bool(work_list) and wl is None)
    has_ev = bool(items) and all(isinstance(i, dict) and "evidence" in i for i in items)
    add("S3", A, "Work items carry an evidence field", 2, has_ev, f"{r.rel(work_list)}: evidence on every item" if has_ev else "",
        "Add an 'evidence' field; an item may only pass when it points at a log, test or file.")
    guard = r.glob("scripts/check_feature_list.py", "**/check_feature_list.py", ".github/workflows/*.yml", ".pre-commit-config.yaml")
    guard_hit = r.grep_any(guard, r"(check_feature_list|feature_list)")
    add("S4", A, "A guard stops agents rewriting the work list (not just updating it)", 3, bool(guard_hit),
        guard_hit, "Add a check that fails if anything other than passes/evidence/next_action changed (pre-commit or CI).")
    add("S5", A, "Progress or hand-off note with the next action", 2,
        bool(progress) and bool(r.grep(progress, r"next (action|step|session)")),
        r.grep(progress, r"next (action|step|session)") if progress else "",
        "Keep progress.md to one screen: where things stand, verdicts, blocker, the single next action.")
    git_root = next((p for p in [r.root, *r.root.parents] if (p / ".git").exists()), None)
    add("S6", A, "Git history exists (checkpoints to resume from)", 2, bool(git_root), f".git at {git_root}" if git_root else "",
        "Initialise git and commit at every checkpoint.")

    dec = r.first("DECISIONS.md", "docs/DECISIONS.md", "docs/decisions", "docs/adr", "adr")
    add("S7", A, "Decisions are written down (DECISIONS.md or ADRs) so later sessions don't relitigate them", 1, bool(dec),
        r.rel(dec) if dec else "", "Add DECISIONS.md: one line per decision, who made it, why, date.")

    # 3. Verification ------------------------------------------------------------------------------
    A = "3 Verification"
    tests = r.glob("tests/**/*", "test/**/*", "**/*_test.go", "**/*.test.*", "**/*.spec.*", "**/test_*.py")
    add("V1", A, "Automated tests exist", 3, bool(tests), f"{len(tests)} test files, e.g. {r.rel(tests[0])}" if tests else "",
        "Add at least one test per work item's done_when.")
    init = r.first("init.sh", "scripts/init.sh", "bin/setup", "scripts/setup.sh")
    add("V2", A, "One command starts and smoke-tests the app (init.sh / make setup)", 2,
        bool(init) or bool(re.search(r"^(setup|init|dev|smoke)\s*:", mk_t, re.M)),
        r.rel(init) if init else r.grep(makefile, r"^(setup|init|dev|smoke)\s*:", re.M),
        "Add init.sh (install, start, smoke test) so every session starts from a known-good state.")
    add("V3", A, "A single 'check' entry point runs the full verification", 2,
        bool(re.search(r"^(check|verify|ci)\s*:", mk_t, re.M)) or '"check"' in mk_t or '"test"' in mk_t,
        r.grep(makefile, r"^(check|verify|ci)\s*:|\"(check|test)\"\s*:", re.M), "Add `make check` (or npm run check) that runs lint, types and tests.")
    verdict = r.grep_any(docs_for_rules + agent_files, r"\b(VERIFIED|INCORRECT|UNRESOLVED)\b", 0)
    add("V4", A, "Claims carry evidence verdicts (VERIFIED / INCORRECT / UNRESOLVED)", 2, bool(verdict), verdict,
        "Require every claim in reports to be marked VERIFIED (with evidence path), INCORRECT or UNRESOLVED.")
    def _desc(p):
        m = re.search(r"^description:\s*(.+)$", r.text(p), re.M)
        return m.group(1) if m else ""
    verifier = next((p for p in agent_files if re.search(r"verif|review|qa|evaluat", p.stem + " " + _desc(p), re.I)), None) or r.first("evaluator-rubric.md", "docs/evaluator-rubric.md")
    add("V5", A, "An independent verifier (subagent or evaluator rubric) checks the work", 1, bool(verifier),
        r.rel(verifier) if verifier else "", "Add a read-only verifier agent that checks an item against done_when before it passes.")

    # 4. Scope and stopping -------------------------------------------------------------------------
    A = "4 Scope and stopping"
    one = r.grep_any(docs_for_rules, r"(one (item|feature|task) at a time|exactly one item|WIP\s*=\s*1|one item only)")
    add("P1", A, "One item at a time (WIP = 1)", 2, bool(one), one, "State: work on one item; do not start a second in the same session.")
    stop = r.grep_any(docs_for_rules, r"(two failed attempts|stop rule|max(imum)? (turns|attempts)|after \d+ (failed )?attempts)")
    add("P2", A, "A stop rule (bounded attempts or turns, then report the blocker)", 3, bool(stop), stop,
        "Add: stop when done_when is met or after two failed attempts at the same step; record the blocker.")
    resume = r.grep_any(docs_for_rules, r"(resume`? (skill|routine)|start (every|each) session with|session[- ]start (routine|checklist)|start of (every|each) session|clock[- ]in|at the start of (a|each|every) session)")
    add("P3", A, "Start-of-session routine (read progress, git log, smoke test)", 2, bool(resume), resume,
        "Add a resume routine: git status, git log -10, read progress, run init.sh, pick one item.")
    ckpt = r.grep_any(docs_for_rules, r"(checkpoint`? (skill|routine)|end (every|each) session with|end[- ]of[- ]session|clock[- ]out|session hand-?off|at the end of (a|each|every) session)")
    add("P4", A, "End-of-session routine (update progress, record evidence, commit)", 2, bool(ckpt), ckpt,
        "Add a checkpoint routine: verify, update the work list and progress note, commit locally.")

    clean = r.first("clean-state-checklist.md", "docs/clean-state-checklist.md") or (r.grep_any(docs_for_rules, r"clean[- ]state") and True)
    add("P5", A, "Clean-state rule before commit (builds, tests pass, no stray files)", 1, bool(clean),
        r.rel(clean) if isinstance(clean, Path) else r.grep_any(docs_for_rules, r"clean[- ]state"),
        "Add a short clean-state checklist the agent runs before every commit and at session end.")
    rush = r.grep_any(docs_for_rules, r"(context anxiety|context runs low|rush(ed)? (to )?finish|finish faster|don.t rush|do not rush|wrap up early|premature(ly)? (declar|finish))")
    add("P6", A, "Warns against rushed finishes when context runs low", 1, bool(rush), rush,
        "Tell the agent: when context runs low, checkpoint and stop cleanly; never declare done to finish faster.")

    # 5. Safety guardrails (beyond the course) -------------------------------------------------------
    A = "5 Safety guardrails"
    deny = r.grep_any(settings, r"\"deny\"")
    add("G1", A, "Permission deny rules exist", 3, bool(deny), deny, "Add .claude/settings.json permissions.deny for secrets and destructive commands.")
    secrets = bool(re.search(r"Read\([^)]*(\.env|\.pem|\.key|\.ssh|\.aws)", settings_t))
    add("G2", A, "Secrets are denied to the agent (.env, keys, credential folders)", 3, secrets,
        r.grep_any(settings, r"Read\([^)]*(\.env|\.pem|\.key|\.ssh|\.aws)"), "Deny Read of .env*, *.pem, *.key, ~/.ssh/**, ~/.aws/**.")
    destructive = bool(re.search(r"Bash\(\s*(git push|git reset --hard|rm -rf)", settings_t))
    add("G3", A, "Destructive commands are denied or gated (push, reset --hard, rm -rf)", 2, destructive,
        r.grep_any(settings, r"Bash\(\s*(git push|git reset --hard|rm -rf)"), "Deny or require approval for git push, reset --hard, rm -rf.")
    iso = r.glob(".devcontainer/devcontainer.json", "**/run-sandboxed.sh", "Dockerfile", "docker-compose.yml")
    sandbox = bool(re.search(r"\"sandbox\"\s*:\s*\{[^}]*\"enabled\"\s*:\s*true", settings_t, re.S))
    add("G4", A, "OS-level isolation for unattended runs (sandbox or container)", 2, sandbox or bool(iso),
        ("settings sandbox enabled" if sandbox else "") or (r.rel(iso[0]) if iso else ""),
        "Permission rules do not stop scripts the agent writes: enable the sandbox or run unattended agents in a container that sees only the repo.")
    env_ignored = bool(re.search(r"^\.env", r.text(r.first(".gitignore")), re.M))
    add("G5", A, ".env files are git-ignored", 2, env_ignored, ".gitignore lists .env" if env_ignored else "", "Add .env and .env.* to .gitignore.")

    # 6. Evals and red teaming (beyond the course) ---------------------------------------------------
    A = "6 Evals and red teaming"
    pf = r.glob("**/promptfooconfig.yaml", "**/promptfooconfig.yml", "**/promptfoo*.yaml")
    add("E1", A, "Behaviour evals for the agent (promptfoo, ADK eval sets, MAF evaluate_agent, …)", 2,
        bool(pf) or bool(r.glob("**/*.evalset.json", "**/*.test.json")),
        r.rel((pf or r.glob("**/*.evalset.json", "**/*.test.json"))[0]) if (pf or r.glob("**/*.evalset.json", "**/*.test.json")) else "",
        "Add a small eval suite: refuses secrets, keeps its instructions, answers with evidence, refuses destructive actions.")
    rt = r.glob("**/redteam*.yaml", "**/red_team*.py", "**/redteam*.yml")
    rt_hit = r.grep_any(rt + pf, r"(redteam|red_team|owasp|jailbreak|prompt-injection)")
    add("E2", A, "Red-team suite (promptfoo redteam or DeepTeam), mapped to OWASP LLM / agentic", 2, bool(rt_hit), rt_hit,
        "Add a red-team run (promptfoo redteam or DeepTeam) covering prompt leakage, excessive agency and injection.")
    ci = r.grep_any(r.glob(".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml"), r"(promptfoo|deepteam|red.?team|eval)")
    add("E3", A, "Evals run in CI, not only by hand", 1, bool(ci), ci, "Run the eval suite in CI on every PR that touches prompts, tools or agent config.")

    # 7. Cost and context (beyond the course) --------------------------------------------------------
    A = "7 Cost and context"
    model_set = r.grep_any(settings, r"\"(model|effortLevel)\"")
    add("C1", A, "Model and effort chosen once, at session start (pinned in settings)", 1, bool(model_set), model_set,
        "Set model (and effortLevel if needed) in settings; avoid mid-session switches, which rebuild the prompt cache.")
    cheap = next((p for p in agent_files if re.search(r"^model:\s*haiku", r.text(p), re.M)), None) or next((p for p in agent_files if re.search(r"^model:\s*sonnet", r.text(p), re.M)), None)
    add("C2", A, "Cheap lookups routed to a smaller model (e.g. Explore on Haiku)", 1, bool(cheap),
        r.grep(cheap, r"^model:", re.M) if cheap else "", "Add a read-only Explore agent with model: haiku that returns file:line evidence.")
    usage = r.grep_any([p for p in (progress, instr) if p] + r.glob(".claude/skills/*/SKILL.md"), r"(tokens? (per|used)|token usage|usage per|wall[- ]clock|/usage|cost per (item|task|run))")
    add("C3", A, "Usage (tokens / time) recorded per accepted item", 1, bool(usage), usage,
        "Record wall-clock time and tokens per accepted item, so you can measure the harness instead of guessing.")
    filt = r.grep_any(settings + r.glob(".claude/hooks/*", "hooks/hooks.json", "**/hooks/hooks.json"), r"(PreToolUse|filter|grep -A)")
    add("C4", A, "Long tool output is filtered before the model sees it (hooks)", 1, bool(filt), filt,
        "Add a PreToolUse hook that shows only failing test output, with the full log on disk.")

    # score -----------------------------------------------------------------------------------------
    rep = Report(repo=str(root))
    rep.checks = [asdict(c) for c in checks]
    total = sum(c.weight for c in checks)
    got = sum(c.weight for c in checks if c.status == "VERIFIED")
    rep.score = round(100 * got / total) if total else 0
    rep.grade = "A" if rep.score >= 85 else "B" if rep.score >= 70 else "C" if rep.score >= 50 else "D"
    for c in checks:
        a = rep.areas.setdefault(c.area, {"verified": 0, "total": 0})
        a["total"] += 1
        a["verified"] += c.status == "VERIFIED"
    return rep


def render_text(rep: Report, color: bool) -> str:
    C = (lambda code, s: f"\033[{code}m{s}\033[0m") if color else (lambda code, s: s)
    mark = {"VERIFIED": C("32", "✓ VERIFIED  "), "MISSING": C("31", "✗ MISSING   "), "UNRESOLVED": C("33", "? UNRESOLVED")}
    out = [C("1", f"Harness audit · {rep.repo}"), ""]
    area = None
    for c in rep.checks:
        if c["area"] != area:
            area = c["area"]
            a = rep.areas[area]
            out.append(C("36;1", f"{area}  ({a['verified']}/{a['total']})"))
        crit = C("31", " [critical]") if c["weight"] == 3 and c["status"] != "VERIFIED" else ""
        out.append(f"  {mark[c['status']]} {c['id']} {c['title']}{crit}")
        if c["status"] == "VERIFIED" and c["evidence"]:
            out.append(C("90", f"               {c['evidence']}"))
        elif c["status"] != "VERIFIED":
            if c["evidence"]:
                out.append(C("90", f"               found: {c['evidence']}"))
            out.append(f"               fix: {c['fix']}")
    out += ["", C("1", f"Score {rep.score}/100 · grade {rep.grade}"),
            "A pass means the harness piece exists in files, not that it works. Run your checks to prove that."]
    return "\n".join(out)


def render_md(rep: Report) -> str:
    out = [f"## Harness audit · score {rep.score}/100 (grade {rep.grade})", "", "| | Check | Evidence or fix |", "|---|---|---|"]
    for c in rep.checks:
        icon = {"VERIFIED": "✅", "MISSING": "❌", "UNRESOLVED": "❓"}[c["status"]]
        detail = c["evidence"] if c["status"] == "VERIFIED" else c["fix"]
        out.append(f"| {icon} | {c['id']} {c['title']} | {detail.replace('|', '/')} |")
    out += ["", f"_harness-audit {rep.version}. A pass means the piece exists in files, not that it works._"]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score a repository's agent harness.")
    ap.add_argument("repo", nargs="?", default=".")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true")
    g.add_argument("--md", action="store_true")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any critical check is not VERIFIED")
    ap.add_argument("--min", type=int, default=0, help="exit 1 if the score is below this")
    ap.add_argument("--version", action="version", version=f"harness-audit {VERSION}")
    a = ap.parse_args(argv)
    root = Path(a.repo).expanduser().resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    rep = audit(root)
    if a.json:
        print(json.dumps(asdict(rep), indent=2))
    elif a.md:
        print(render_md(rep))
    else:
        print(render_text(rep, sys.stdout.isatty() and not os.environ.get("NO_COLOR")))
    failed_crit = any(c["weight"] == 3 and c["status"] != "VERIFIED" for c in rep.checks)
    return 1 if (a.strict and failed_crit) or rep.score < a.min else 0


if __name__ == "__main__":
    sys.exit(main())
