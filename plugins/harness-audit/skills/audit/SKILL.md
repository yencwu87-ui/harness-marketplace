---
name: audit
description: Score this repository's agent harness across 7 areas and list exactly what to fix. Use when asked to audit, review, score or check a harness, or before setting one up.
---

# Harness audit

1. Run the audit script that sits next to this file, against the project root (read-only, no dependencies):
   ```bash
   python3 "<this skill's base directory>/scripts/audit.py" . --md
   ```
2. Show the user the score and the table. Then, in plain words, list the **critical** gaps first (marked ❌ with weight 3), then the rest, grouped by area.
3. For each gap, say the smallest fix. If the `harness-init` plugin is installed, say which gaps `/harness-init:init` would close.
4. Do not change any files during an audit. Offer to fix; wait for a yes.

Notes for the user:
- A pass means the harness piece exists in files, not that it works. The proof is running the checks.
- `--json` gives machine-readable output for CI; `--strict` exits 1 when any critical check fails; `--min 70` fails below a score.
- Areas 1–4 (instructions, state, verification, scope) follow WalkingLabs' Learn Harness Engineering course. Areas 5–7 (safety guardrails, evals and red team, cost and context) are what production teams add on top.
- Other frameworks: the audit detects LangGraph, OpenAI Agents SDK, CrewAI, Strands, Google ADK, Microsoft Agent Framework and the Claude Agent SDK from the repo's imports (read, never run) and checks their own guard mechanisms for G1–G3. For assess-only frameworks, what `docs/IMPACT.md` states counts as DECLARED, at half weight.
- Credit only what is proven: a guard counts only when it is attached to the scored agent and tool. A narrower, conditional or unreadable guard is UNRESOLVED with the reason, never VERIFIED. A capability the audit cannot rule out is reported, never assumed absent.
- From 1.4.4, a code refusal (inside a tool, or in a framework hook) earns credit only in one of the canonical forms below; any other shape is UNRESOLVED with the reason, even when it is correct. `audit.py --canonical-forms` prints the same list. Permission rules (Claude Code settings and Agent SDK `disallowed_tools`) follow one standard: a scoped rule covers only its scope. With Claude Code's sandbox, Read deny rules count for Bash only when no command can leave the sandbox (`allowUnsandboxedCommands: false`, no `excludedCommands`), and a whole-Bash ask counts only with `autoAllowBashIfSandboxed: false`.

## Canonical guard forms

How to earn the points: put the refusal first in the tool (or hook), test the tool's own input, and join tests with `or`.

```python
import kit_guard                      # copy kit/shared/kit_guard.py into your repo unchanged

def run(command: str) -> str:
    if kit_guard.refuses(command):    # or: if '.env' in command or 'rm -rf' in command or 'git push' in command:
        return "refused"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
```

<!-- canonical-forms:start (generated from CANONICAL_FORMS in scripts/audit.py; a test keeps them equal) -->
- **F1 Position.** The refusal is `if <predicate>: <refusal>`, a statement of the guard function's own body (its top level), before the capability call. Not inside a loop, `with`, `try`, `match`, another `if`, a nested function or a comprehension. In a hook, no earlier top-level statement may return, raise, await, or use the continuation (`call_next`, even through another name) without refusing. The guard function has no decorator except the framework's own (or staticmethod, classmethod), and no file in the repo changes its module at run time (globals(), vars(), exec, setattr or an attribute store on its functions, classes or constants).
- **F2 Tool scope (hooks only).** A hook may limit a refusal to named tools: `if <tool name> == '<literal>' and (<predicate>):`, the same with `in (<literals>)`, or a top-level `if <tool name> == '<literal>':` whose own body holds the refusing `if`. The tool name is exactly the framework's own field: `tool.name` (Google ADK), `ctx.tool_name` (CrewAI), `event.tool_use['name']` (Strands), `context.function.name` (Microsoft Agent Framework), `input_data['tool_name']` or `.get('tool_name')` (Claude Agent SDK).
- **F3 Refusal.** Inline tool and Microsoft Agent Framework middleware: `return ...` or `raise ...`. CrewAI hook: `return False`. Google ADK before_tool_callback: `return {...}`. Strands: `event.cancel_tool = '<message>'`, and nothing else in the hook sets cancel_tool to anything but a message. Claude Agent SDK PreToolUse hook: a return of a dict with `permissionDecision: 'deny'` (nested in hookSpecificOutput), or of a call to a repo function whose every return is one, with no repeated key and no `**` unpacking in those dicts. A body that uses the hook's continuation (`call_next`) lets the call through.
- **F4 Predicate.** One or more tests joined only by `or`, each one of: `'<literal>' in V`; `'<literal>' not in V`; `V == '<literal>'`; `V.startswith(<literal or tuple of literals>)`; `re.search|re.match|re.fullmatch(r'<literal>', V[, re.I|re.M|re.S])`; `NAME.search|match|fullmatch(V)` where NAME is a module constant assigned once to `re.compile(r'<literal>'[, flags])`; `any(x in V for x in <tuple of literals>)`; `kit_guard.refuses(V)`, the kit's shipped helper, only while its file's sha256 equals the pinned KIT_GUARD_SHA256. A literal may be a module constant assigned once. Any `and` (other than F2), `not`, other call, or other operand is not canonical. `any`, `str`, `repr`, `re` and `json` must be the real ones: not defined, assigned or imported under that name in the module, and `builtins`, `re`, `json` and `kit_guard` not changed at run time anywhere in the repo.
- **F5 Value in a tool.** V is a parameter of the tool function that is never rebound, reassigned, augmented, deleted or changed in place anywhere in the function, and the capability call receives that same name as is (a bare argument, not sliced, field-selected, wrapped or converted). A helper call counts when it receives the name as is and its own parameter is in turn passed as is to the capability.
- **F6 Value in a hook.** V is the whole tool input as text: `str(...)`, `json.dumps(...)` or `repr(...)` of exactly the framework's input: `args` (Google ADK, the second parameter), `ctx.tool_input` (CrewAI), `event.tool_use` or `event.tool_use['input']` (Strands), `context.arguments` (Microsoft Agent Framework), `input_data` or `input_data['tool_input']` (Claude Agent SDK, the first parameter), `data.context.tool_arguments` (OpenAI tool input guardrail); `kit_guard.refuses` may take that input without `str`. Any other object is not the input. In a Claude Agent SDK PreToolUse hook V may instead be one field of `tool_input` that a built-in tool executes: `command` (covers Bash only) or `file_path` (covers Read, Write, Edit and MultiEdit only). A local name assigned once, at the top level of the hook, to one of these counts as it. The parameter it is read from must never be rebound or changed in place (`ctx.tool_input = {}`, `args.clear()`).
- **F7 Coverage.** A class is covered when, for at least one of its keywords, the predicate is true on every probe of the keyword K: `K`, `K x`, `cat K`, `x;K`, `echo ok; K --flag`, `echo ok` then K on the next line, K in single quotes, double quotes, backticks and parentheses, `a/K/b` and `a/K.local`. Secrets: .env, .pem, .key, .ssh, .aws, id_rsa, credentials. Destructive: git push, reset --hard, rm -rf. A regex anchored with ^ or $, run with re.match or re.fullmatch, or otherwise missing one probe does not cover the keyword. When V is the whole input as text, each probe is first put through the same str(), repr() or json.dumps() (as the value of a dict), which escapes a newline. `not in` and `==` tests are allowed in a predicate but never count toward coverage. kit_guard.refuses covers both classes.
<!-- canonical-forms:end -->

What these forms leave out, on purpose (each is UNRESOLVED, no points): allow-lists (`if not ALLOWED.match(cmd)`), a refusal and a capability under the same condition, refusals inside `try`, loops or another `if`, helper functions other than the pinned `kit_guard.refuses`, checks on a converted or reassigned value, and hooks that return early for some tools before refusing. Rewrite such a guard in a canonical form to earn its points.
