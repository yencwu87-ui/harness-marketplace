# Track spec: `harness_track.json` (schema `harness-track/1`)

Every folder under `kit/tracks/<id>/` has one `harness_track.json`. Tools that read a harness (the kit's
own Makefile and tests, and assessors such as OpenProof) use it to tell which framework a repo is built
on, where its tool-call trace comes from, and which files describe what the agent can reach.

```json
{"schema":"harness-track/1","id":"<id>","name":"<display>","language":"python|typescript",
 "support":"full|assess-only","framework":{"package":"<pip/npm name>","version":"<pinned>"},
 "entry":"<file>","tool_hook":{"kind":"callback|middleware|event|wrapper","where":"<file:symbol>"},
 "reach_sources":[{"file":"<path glob>","kind":"<parser key>"}],
 "detect":[{"file":"<glob>","contains":"<string>"}],
 "notes":"<one line>"}
```

## Fields

| Field | Meaning |
|---|---|
| `schema` | Always `harness-track/1`. |
| `id` | The folder name; also the `TRACK=` value for `make`. |
| `name` | Display name. |
| `language` | `python` or `typescript`. Claude Code is config-only; it is marked `python` because its hook script and the kit's tools are Python. |
| `support` | `full`: the kit ships a starter agent wired to `shared/target.py`, a pinned `requirements.txt`, a tool-call trace hook for the live red team, and an offline smoke test. `assess-only`: the kit ships only this file and a short README, so an assessor can detect and audit a harness built on it. No starter or trace hook yet. |
| `framework` | The package that defines the framework and the version this track was checked against (pip name for Python, npm name for TypeScript). |
| `entry` | The starter file, relative to the track folder. `null` for `assess-only`. |
| `tool_hook` | How every tool call reaches `$HARNESS_TRACE`. `kind` is the framework's own mechanism (`callback`, `middleware`, `event` or `wrapper`), and `where` is `<file>:<symbol>`, relative to the track folder. `null` for `assess-only`. |
| `reach_sources` | Files that describe what the agent can reach (tools, permissions, MCP servers, keys by name). `file` is a glob relative to the harness repo root. `kind` must be one of the parser keys below. |
| `detect` | Signatures that identify a repo built on this framework. A repo matches when any file matching `file` (a glob relative to the repo root) contains `contains`. An empty `contains` means the file only has to exist. |
| `notes` | One line. |

## Parser keys for `reach_sources[].kind` (fixed list)

| Key | Reads |
|---|---|
| `claude_settings` | Claude Code `settings.json`: permissions allow/ask/deny, hooks, sandbox, network |
| `mcp_json` | `.mcp.json` MCP server list |
| `env_example` | `.env.example`: key names only, never values |
| `python_tool_list` | Python tool functions passed to an agent (`tools=[...]`, `@tool`) |
| `openai_agents_tools` | OpenAI Agents SDK `@function_tool` functions and `Agent(tools=[...])` |
| `langgraph_tools` | LangChain `@tool` functions and `create_react_agent(model, tools)` |
| `crewai_tools` | CrewAI `@tool("name")` functions and `Agent(tools=[...])` |
| `strands_tools` | Strands `@tool` functions and `Agent(tools=[...])` |
| `generic_declared` | Nothing to parse: the assessor relies on what the developer declares (`docs/IMPACT.md`, `.harness/REASONS.md`) and says so ("reach declared, not derived") |

## Trace line format (all full tracks)

One JSON object per line, appended to the file named by `$HARNESS_TRACE`:

```json
{"ts": 1730000000.0, "source": "<track hook name>", "tool": "<tool name>", "input": {...}}
```

The hooks only observe. They return without changing the call, so the agent's own rules still decide what runs.

## Adding a track

1. Copy the closest full track. Keep `next_item` and `run_init`, the `ask(prompt)` coroutine and the `--repo` / `--ask` CLI.
2. Write the trace hook with the framework's own mechanism, and point model calls at a base URL from the environment.
3. Add the track to `shared/target.py`, the `TRACKS` list and the `run` target in `kit/Makefile`, `CHOOSING.md` and the README table.
4. Add an offline smoke test in `tests/test_tracks.py`, driven by `tests/llm_stub.py`, with no hosted model calls.
