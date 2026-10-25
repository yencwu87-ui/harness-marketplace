# Harness Starter Kit

Build AI agents that can work on a long task, stop, and pick up where they left off,
without losing their place, touching what they shouldn't, or calling work "done" without proof.

**Pick your environment. Keep the same discipline.** The kit gives every option the same work
list, the same stop rule and the same evidence format, plus one test suite that runs against
any of them.

```
  Build ──► Verify ──► Checkpoint ──► Resume        + Test (evals and red team) on any track
```

## 1. Choose your path

| If you want… | Track | Language | Models |
|---|---|---|---|
| An AI pair-programmer in your terminal or IDE, today | **[Claude Code](tracks/claude-code/)** | none (config only) | Claude |
| The Claude Code harness inside your own app or CI job | **[Claude Agent SDK](tracks/claude-agent-sdk/)** | Python (also TypeScript) | Claude |
| Enterprise agents on Azure, workflows, .NET or Python | **[Microsoft Agent Framework](tracks/microsoft-agent-framework/)** | Python (also .NET) | Claude, OpenAI, Azure/Foundry, Ollama |
| Agents on Google Cloud, with a web debugger and built-in evals | **[Google ADK](tracks/google-adk/)** | Python (also Java, Go, TS) | Claude, Gemini, any LiteLLM model |

Not sure? Read [CHOOSING.md](CHOOSING.md) (two minutes).

## 2. Choose where it runs

| Environment | Use when | How |
|---|---|---|
| **Local** (macOS, Linux, Windows via WSL2) | Fastest start, solo work | `make setup TRACK=…` |
| **Dev Container / Codespaces** | Same tools for the whole team, no "works on my machine" | `make devcontainer`, then "Reopen in Container" |
| **Locked-down Docker** | Agent must not see your home folder, SSH keys or cloud credentials | `environments/docker/run-sandboxed.sh /path/to/repo` |

## 3. Choose how you test it

| Tool | What it's for | Run |
|---|---|---|
| **[promptfoo](testing/promptfoo/)** | Behaviour evals in YAML, side-by-side model comparison, automated red team (OWASP LLM and agentic plugins), CI-friendly | `make eval` · `make redteam-promptfoo` |
| **[DeepTeam](testing/deepteam/)** | Python red teaming: 40+ vulnerability types, single- and multi-turn attacks, OWASP Top 10 for LLMs and OWASP agentic (ASI 2026) frameworks | `make redteam-deepteam` |
| Built-in | ADK: `adk eval`. Microsoft Agent Framework: `evaluate_agent`. Claude Code: the `verifier` agent | per track |

Both test tools call your agent through one adapter (`shared/target.py`), so the same suite runs
against whichever track you picked. Set `KIT_TRACK`.

## 4. Start (about 30 minutes)

```bash
# put the kit inside your repo
cd your-repo && git clone <this kit> harness      # or unzip it as ./harness
cd harness

make install TRACK=claude-code       # copies the work list, init.sh, checks (+ Claude Code files) into your repo
make setup   TRACK=claude-code       # installs what the track needs
make smoke                           # offline check that the test wiring works (no API key)
cp .env.example ../.env              # add only the keys your track needs
```

Then:

1. Fill in `CLAUDE.md` (Claude tracks), `init.sh` and three items in `progress/feature_list.json`,
   each with a `done_when` you can check without asking anyone.
2. `make run TRACK=…` to work on the first failing item.
3. `make check` to confirm the work list was only updated, not rewritten.
4. `make eval TRACK=…` and one red-team run before you trust it with more.

## What every track shares

| File | Purpose |
|---|---|
| `progress/feature_list.json` | The work list. Agents change only `passes`, `evidence`, `next_action`. |
| `progress/progress.md` | One screen: where things stand, verdicts, usage, the single next action. |
| `scripts/check_feature_list.py` | Fails if anything else in the work list changed. Use in pre-commit or CI. |
| `init.sh` | Starts and smoke-tests your app so each session begins from a known-good state. |
| Stop rule | Stop when `done_when` is met, or after two failed attempts. Record the blocker. |
| Verdicts | Every claim is VERIFIED (with evidence), INCORRECT, or UNRESOLVED (what's missing). |

## Guardrails: be clear about what protects what

| Layer | Stops | Doesn't stop |
|---|---|---|
| Permission rules (Claude Code deny rules, MAF tool approval, SDK hooks) | The agent's own tools reading secrets or running listed commands | A script the agent writes from opening a file |
| Shell sandbox (Claude Code / Agent SDK `sandbox`) | Shell commands reaching paths and hosts outside the allowed set | Non-shell tools; depends on OS support |
| Container (`run-sandboxed.sh`) | Everything outside the mounted repo, for every process | What's inside the repo itself, and any key you pass in |
| Red team (promptfoo, DeepTeam) | Finds weaknesses before users do | Nothing at run time; it's a test |

## Honest expectations

Results depend on the workload and how you measure them. None of the sources promise a
percentage gain. Measure your own baseline: tokens, cost and wall-clock time per accepted item,
before and after. The Agent SDK track logs this to `progress/usage.log` automatically.

Versions this kit was checked against (25 Oct 2026): claude-agent-sdk 0.2.174, agent-framework
1.23.0 (Anthropic connector pre-release), google-adk 2.13.0, deepteam 1.0.10, promptfoo 0.125.1.
Model ids such as `claude-sonnet-5-5` are defaults you can override in `.env`.

## Sources

- Claude Code: [model configuration](https://code.claude.com/docs/en/model-config) ·
  [subagents](https://code.claude.com/docs/en/sub-agents) · [costs](https://code.claude.com/docs/en/costs) ·
  [prompt caching](https://code.claude.com/docs/en/prompt-caching)
- Anthropic: [Effective harnesses for long-running agents](https://www.anthropic.com/research/effective-harnesses-for-long-running-agents)
- [Microsoft Agent Framework 1.0](https://devblogs.microsoft.com/agent-framework/microsoft-agent-framework-version-1-0/)
- [Google ADK (adk-python)](https://github.com/google/adk-python)
- [promptfoo](https://www.promptfoo.dev/) (MIT; OpenAI announced its acquisition 9 Mar 2026 and said it stays open source)
- [DeepTeam](https://github.com/confident-ai/deepteam)
