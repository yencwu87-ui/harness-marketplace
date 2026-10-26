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
   - AWS / Bedrock → **AWS Strands Agents** (Bedrock provider, AWS-native).
   - Neither → **Claude Agent SDK**, or MAF/ADK with the Anthropic connector.

4. **Is your team already using an open-source agent framework?** Stay on it:
   - Graphs, explicit state, resume by thread → **LangGraph**.
   - OpenAI-style agents with handoffs and guardrails, on any OpenAI-compatible endpoint → **OpenAI Agents SDK**.
   - Role-based "crews" of agents with tasks → **CrewAI**.

## Side by side

| | Claude Code | Claude Agent SDK | Microsoft Agent Framework | Google ADK |
|---|---|---|---|---|
| Best at | Coding in a repo | Coding agents you embed | Multi-agent workflows, enterprise integration | Multi-agent apps, eval loop, Google Cloud |
| You write | Config + Markdown | Python or TypeScript | Python or C# | Python (also Java, Go, TS) |
| Models | Claude | Claude | Claude, OpenAI, Azure, Bedrock, Gemini, Ollama… | Gemini, Claude, LiteLLM models |
| Built-in harness pieces | Skills, subagents, hooks, sandbox, compaction, checkpoints | Same as Claude Code | `create_harness_agent`: todo list, plan/execute mode, file memory, compaction, tool approval | Sessions, state, callbacks, `adk eval`, web debugger |
| Built-in testing | `verifier` agent (in kit) | Your own tests + kit suites | `evaluate_agent`, kit suites | `adk eval`, `adk web`, kit suites |
| Maturity (Oct 2026) | GA | 0.2.x, actively released | 1.x GA core; some connectors pre-release | 2.x stable releases |

| | LangGraph | OpenAI Agents SDK | CrewAI | AWS Strands Agents |
|---|---|---|---|---|
| Best at | Stateful graphs, resume by thread, human-in-the-loop | Small, readable agents with handoffs and guardrails | Role-based multi-agent crews and flows | Model-driven agents on AWS / Bedrock |
| You write | Python (also JS) | Python (also TypeScript) | Python | Python (also TypeScript) |
| Models | Claude, OpenAI, many via LangChain | Any OpenAI-compatible endpoint | Claude, OpenAI, Bedrock, Gemini, Azure, local… | Bedrock, Claude, OpenAI, others |
| Trace hook in the kit | LangChain callback `on_tool_start` | `RunHooks.on_tool_start` | before-tool-call hook | `BeforeToolCallEvent` hook |
| Version checked (26 Oct 2026) | langgraph 1.2.17 | openai-agents 0.24.0 | crewai 1.15.30 | strands-agents 1.62.0 |

## Assess-only tracks

OpenProof (or any assessor that reads `tracks/*/harness_track.json`) can detect and audit a harness built
on these. The free kit doesn't ship a starter or trace hook for them yet. Versions checked on 26 Oct 2026:

| Framework | Package | Language |
|---|---|---|
| LlamaIndex agents | llama-index-core 0.14.25 | Python |
| Pydantic AI | pydantic-ai 2.61.0 | Python |
| smolagents (Hugging Face) | smolagents 1.26.0 | Python |
| Haystack | haystack-ai 3.4.1 | Python |
| DSPy | dspy 3.4.1 | Python |
| Agno | agno 3.1.10 | Python |
| Mastra | @mastra/core 1.79.0 | TypeScript |
| Vercel AI SDK | ai 7.0.153 | TypeScript |

**AutoGen and Semantic Kernel** are not separate tracks. Microsoft describes Agent Framework (1.0 GA,
3 Apr 2026) as the successor to Semantic Kernel for building agents, and it brings in AutoGen's
orchestration patterns. Both older projects still receive fixes, but new agent work belongs on the
**Microsoft Agent Framework** track.

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
