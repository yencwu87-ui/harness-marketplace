# Changelog

## 1.4.3 (27 Oct 2026)
Fix round for Codex's round-2 review of 1.4.2 (6 P1). Each finding first got a failing test, using the reviewer's fixtures (`tests/fixtures/codex_r2/`). The rule for this round: **credit only what is proven**.
- **Refusals must hold on every path (harness-audit 1.4.3, R2-01).** A refusing condition is split into its OR-branches; a branch covers secrets or destructive commands only when every part of it tests the tool's input for that class. A refusal nested under a flag or another tool's name, behind an earlier pass-through exit, inside `try`/`while`/`match`, inverted (`not ...`, `not in`, `is False`) or matching exact values only is UNRESOLVED with the reason, never VERIFIED. An AND of two classes covers neither. Combining hook conditions keeps each one's restrictions.
- **CrewAI `Task(human_input=True)` is not a per-call approval (R2-02):** a person reviews the task's final answer after the tools have run. It earns no G1-G3 credit and is never credited to another agent.
- **Reach never drops a capability silently (R2-03):** local and module aliases (`runner = subprocess`), `Path(p).open()`, and fixed commands are followed. A fixed `git push` is an irreversible action that needs a gate; a fixed `git status` is listed in the evidence. Computed calls (`getattr(...)(...)`) and methods on objects the audit cannot follow are UNRESOLVED.
- **Agent SDK MCP tools bind to their server (R2-04):** the implementation is the one passed to `create_sdk_mcp_server(tools=[...])` for that key of `mcp_servers`, whatever the declaration order; unreadable or external servers are UNRESOLVED. Any `allowed_tools` rule for a tool (for example `Bash(*)`) auto-approves it.
- **Claude Code rules keep their scope (R2-05):** a scoped `ask` or `deny` rule covers only its scope (`Bash(git status *)` gates nothing else; `Bash(git push origin main)` is narrower than `Bash(git push *)`; `Read(./config/.env)` is narrower than `Read(./**/.env)`). `ask` outranks `allow`. With the sandbox enabled, Read deny rules also bind Bash. A settings file the audit cannot read makes the checks UNRESOLVED.
- **The audit reads only the repo:** it never opens secret-looking files and never follows a symlink out of the audited tree; a guard or setting that lives behind such a link earns nothing.
- **Agent SDK starter: links are checked, not names (R2-06).** `search_code` resolves every file before opening it and skips targets that are secret or outside the repo (`ordinary.txt -> .env` no longer leaks); links that stay inside the repo to ordinary files still work. The PreToolUse hook refuses file tools through such links.
- **CI:** the base-comparison test no longer calls `git show 24bc1da:...` (which fails in GitHub's shallow checkout and in downloads without `.git`); 1.4.1's `audit.py` is vendored under `tests/fixtures/audit_1_4_1/`, pinned by git blob id and sha256, and a mismatch fails.
- **Generated near-miss tests (`tests/test_audit_nearmiss.py`):** for every guard kind the audit credits, a positive earns full credit and one-change variants earn none (narrower scope, another agent, another MCP server or implementation, a condition, a symlink, a Boolean that reads true but means false). 78 of its subtests fail on 1.4.2.
- Unchanged: the eight-track fairness matrix (a=8, b=0, c=2 on every track), the kit starters (8/8 on every full track), assess-only declarations (4/8). Other plugins stay at 1.4.2.

## 1.4.2 (27 Oct 2026)
Fix round for an independent review (Codex, round 1) of 1.4.1: 6 P1 and 5 P2 findings. Each finding first got a failing test, using the reviewer's fixtures (`tests/fixtures/codex_r1/`).
- **Guard credit follows attachment (harness-audit 1.4.2).** A guard counts only when it is attached to the agent and the tool being scored and covers that capability. Two agents in one framework no longer share credit; comments, unused constants and unregistered hooks earn nothing; a guard the audit cannot read is UNRESOLVED, never VERIFIED. On the reviewer's matrix every track now scores a=8, b=0, c=2 (1.4.1: c=8 everywhere, and Claude Code b=3).
- **Tools are followed statically:** local definitions, import aliases (`import subprocess as sp`) and imported tool modules are resolved with `ast`, without importing them. Anything the audit cannot follow is UNRESOLVED.
- **Equal refusals earn equal credit:** an inline early-return refusal in a tool earns the same as a framework hook. A refusal whose condition the audit cannot read is UNRESOLVED, not MISSING. A hook that refuses secrets in one condition and destructive commands in another covers both.
- **Claude Code G1 needs deny rules that apply:** an empty, missing or irrelevant deny list earns no G1.
- **Live presets run the production agent:** the `claude-agent-sdk` and `microsoft-agent-framework` presets now call `--task`, which runs the work agent with its real tools, instructions and trace hook (`--ask` stays tool-free for the prompt suites). Offline integration tests drive both through stand-in frameworks: a planted file is read through the production tool path, the trace records it, and a detector trips.
- **A failed run is never VERIFIED (harness-redteam 1.4.2):** a failed start, nonzero exit, timeout or failed isolation start is UNRESOLVED with diagnostics, and `run` / `selftest` exit nonzero. Violations seen before a failure still make the run INCORRECT.
- **Agent SDK starter: content search cannot reach secrets.** The built-in `Grep` and `Glob` are no longer offered (their globs and roots could reach secret files); `mcp__kit__search_code` searches the repo and never opens secret files. The hook also refuses recursive shell searches, destructive commands and writes outside the repo. The `explore` subagent gets the same restricted tools.
- **`harness verify` refuses runs that change files (harness-init 1.4.2):** tracked source, pinned files or new untracked files changed during the checks make the run UNRESOLVED and exit nonzero; ignored build output and caches are still allowed. `harness check` fails on uncommitted changes outside `progress/` and `.harness/` (`--allow-dirty` reports them as UNRESOLVED instead).
- **Smoke tests:** a smoke skips when the framework or its provider connector is missing and fails when an installed one breaks; conflicting `KIT_PROVIDER` / `KIT_MODEL` / base-URL variables are cleared and sentinels prove requests reach only the local stub. The file-writing harness test passes with `PYTHONDONTWRITEBYTECODE` set and unset. CrewAI's trace hook is registered once per process.

## 1.4.1 (26 Oct 2026)
- **Fair guard scoring (harness-audit 1.4.1).** Before this release, G1–G3 (8 of the guard points) were awarded only from `.claude/settings.json`, so a well-guarded harness on any other framework scored 0 of 8. The audit now detects the framework statically and checks that framework's own equivalent:
  - an explicit tool list;
  - broad tools (shell or code execution, write anywhere, web fetch, computer use) gated by its approval or deny step: `needs_approval` / tool input guardrails, `interrupt` / `HumanInTheLoopMiddleware`, a CrewAI before-tool-call hook returning False or `human_input`, Strands `cancel_tool`, ADK `before_tool_callback`, Agent Framework `approval_mode`, Agent SDK `disallowed_tools` / PreToolUse deny;
  - secret-path and destructive-command refusals.

  Narrow harnesses now get 8 of 8 on every supported track. The same broad tool loses the same points on every track: shell or computer use 8, web fetch 6, write anywhere 5. Every result keeps file:line evidence, and every fix names the framework's mechanism.
- **Declared evidence:** for assess-only frameworks, what `docs/IMPACT.md` states is marked DECLARED and earns half a check's weight. Derived evidence always takes precedence over declared evidence.
- **Several agent surfaces:** a guard check passes only when every agent surface in the repo passes it (Claude Code settings and each detected framework).
- **Other checks:** V5, E1, C1, C2 and C4 also accept framework equivalents (a verifier agent, `evaluate_agent`, a pinned model id, a smaller lookup model, truncated tool output), but only when a framework is detected.
- **Unchanged and safe:** Claude Code-only repos score exactly as before. Detection reads imports with `ast`, never imports or runs the audited repo, and ignores test files.
- `tests/test_audit_fairness.py` adds the fairness matrix across 7 tracks, native broad tools, declared scoring, a no-execution check, and a check that the embedded track signatures match `kit/tracks/*/harness_track.json`.

## 1.4.0 (26 Oct 2026)
- **Four more tracks, supported (full):** LangGraph (langgraph 1.2.17), OpenAI Agents SDK (openai-agents 0.24.0), CrewAI (crewai 1.15.30) and AWS Strands Agents (strands-agents 1.62.0). Each has a starter wired to `shared/target.py`, a pinned `requirements.txt`, model calls that can point at a gateway (base URL from the environment), and a tool-call trace for the live red team that uses the framework's own hook (LangChain callback, `RunHooks`, before-tool-call hook, `BeforeToolCallEvent`).
- **Eight assess-only tracks:** LlamaIndex, Pydantic AI, smolagents, Haystack, DSPy, Agno, Mastra and Vercel AI SDK. Each has a spec file and a short README so an assessor can detect and audit a harness built on it. The kit ships no starter or trace hook for them yet.
- **Track spec:** every track has a `harness_track.json` (`harness-track/1`, see `kit/tracks/TRACK_SPEC.md`), the four existing tracks included.
- **Live red team:** `"track": "<id>"` in `live.json` fills in that track's agent command. Code tracks write their own trace, so the Claude Code hook is not installed for them.
- **Offline smoke tests:** `tests/test_tracks.py` drives one tool call through each new track against `tests/llm_stub.py` (a local Anthropic/OpenAI-shaped stub on 127.0.0.1) and checks that the trace recorded it. The tests skip when a framework isn't installed.
- harness-redteam 1.4.0 (its skill names the track presets). `make setup` uses `--pre` only for Microsoft Agent Framework. AutoGen and Semantic Kernel are noted under Microsoft Agent Framework rather than given tracks of their own.

## 1.3.0 (25 Oct 2026)
- **Independent re-execution:** `harness reverify` re-runs every passing item's checks on the current machine, writes nothing, and fails if any fail. The CI template now runs `check` then `reverify` and fails properly (1.1's template did not).
- **Environment pinning:** dependency lockfiles (requirements, poetry, uv, npm, pnpm, yarn, Cargo, go.sum, …) are pinned automatically; evidence records fingerprint git-ignored local files that could affect tests.
- **Forced egress for the live red team:** `"isolation": "netns"` runs the agent in a Linux network namespace with no network except the logging proxy (through `bridge.py`); `"docker"` does the same in a container with `--network none` (experimental). The self-test now proves isolation: a direct connection is blocked and a proxied one is logged.
- **Runtime parity:** the served model, tools and MCP servers are read from the agent's own init event; a model that differs from production is a violation.
- `docs/HARDENING.md` (CODEOWNERS, branch protection, signed commits, CI proof) and `docs/LIVE-RUN.md` (the first live run).
- 37 tests.

## 1.2.0 (25 Oct 2026)
- **Pinned files:** approval now records hashes of every file the criteria depend on: files named in check commands (pytest node ids included) plus optional `pins` globs (e.g. fixtures). `verify` refuses and `check` fails if a pinned file changed, disappeared or a new one appeared in a pinned folder, until a person approves again. Closes the "weaken the test, then verify" gap. 5 new tests (18 in total for the binding).

## 1.1.0 (25 Oct 2026)
- **Evidence binding:** `tools/harness.py` (approve / verify / signoff / retire / check / status). Executable `done_when` checks, criteria fingerprints, hash-chained ledger, code fingerprint, runner-only passes. 13 tests.
- **Live red team:** `tools/redteam_live/` runs generated attacks through the real agent command with canaries, a tool trace, a trap remote and an egress proxy; deterministic verdicts; config parity against a production baseline; detector self-test. promptfoo and DeepTeam bridges. 5 tests.
- Trace hooks in the Claude Agent SDK, Google ADK and Microsoft Agent Framework tracks.
- harness-audit 1.1.0: new checks S8 (criteria bound to evidence) and E4 (red team on the real tool path).
- CI runs all unit tests, the copy-sync check and the live self-test.

## 1.0.2
- harness-audit finds decisions logs in nested folders.

## 1.0.1
- harness-audit: fewer false passes (I3, P3, P4, C3); one directory walk, about 2 s on large repos.

## 1.0.0
- Four Claude Code plugins (audit, init, core, redteam) and the multi-framework kit.
