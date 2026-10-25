# Choosing a track (two minutes)

Answer the first question that applies.

1. **Do you just want help writing and changing code in your own repo?**
   → **Claude Code.** No code to write; the harness is config, skills and two helper agents.

2. **Do you need the agent to run unattended: in CI, on a schedule, or inside your product?**
   - Claude models are fine → **Claude Agent SDK.** Same tools and harness as Claude Code, driven from Python.
   - You must stay model-neutral or run on Azure → **Microsoft Agent Framework.**
   - You run on Google Cloud or want Gemini as an option → **Google ADK.**

3. **Does your company already standardise on a cloud?**
   - Azure / Microsoft 365 / .NET shop → **Microsoft Agent Framework** (Foundry, Entra, .NET support).
   - Google Cloud / Vertex AI → **Google ADK** (Vertex deployment, built-in eval, web UI).
   - Neither, or AWS → **Claude Agent SDK**, or MAF/ADK with the Anthropic or Bedrock connector.

## Side by side

| | Claude Code | Claude Agent SDK | Microsoft Agent Framework | Google ADK |
|---|---|---|---|---|
| Best at | Coding in a repo | Coding agents you embed | Multi-agent workflows, enterprise integration | Multi-agent apps, eval loop, Google Cloud |
| You write | Config + Markdown | Python or TypeScript | Python or C# | Python (also Java, Go, TS) |
| Models | Claude | Claude | Claude, OpenAI, Azure, Bedrock, Gemini, Ollama… | Gemini, Claude, LiteLLM models |
| Built-in harness pieces | Skills, subagents, hooks, sandbox, compaction, checkpoints | Same as Claude Code | `create_harness_agent`: todo list, plan/execute mode, file memory, compaction, tool approval | Sessions, state, callbacks, `adk eval`, web debugger |
| Built-in testing | `verifier` agent (in kit) | Your own tests + kit suites | `evaluate_agent`, kit suites | `adk eval`, `adk web`, kit suites |
| Maturity (Oct 2026) | GA | 0.2.x, actively released | 1.x GA core; some connectors pre-release | 2.x stable releases |

## Which test tool?

- **Start with promptfoo** if your team likes YAML, wants CI gates, or wants to compare models side by side.
  Its red team covers OWASP LLM and agentic categories.
- **Add DeepTeam** if your team works in Python and wants fine-grained vulnerability types and multi-turn
  jailbreak attacks mapped to OWASP Top 10 for LLMs or the OWASP agentic list (ASI 2026).
- They overlap. Running both on a release candidate is a cheap second opinion.

## Which environment?

- **Local** to learn. **Dev Container** once two or more people share the repo.
- **Locked-down Docker** whenever the agent runs unattended or near anything sensitive.
  It's the only option here that limits every process, not just the agent's own tools.
