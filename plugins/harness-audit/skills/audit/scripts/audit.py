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
import ast
import builtins
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

VERSION = "1.4.3"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target", "site-packages", "third_party", "vendor"}
MAX_FILES = 60000
MAX_FILE_BYTES = 400_000
# Files the audit never opens: environment files (templates such as .env.example are fine), keys and credentials.
SECRET_FILE = re.compile(r"^(\.env(\.(?!example$|sample$|template$|dist$)[^/]*)?|.*\.(key|pem|p12|pfx)|"
                         r"id_(rsa|dsa|ecdsa|ed25519)|\.netrc|credentials(\.json)?)$")


@dataclass
class Check:
    id: str
    area: str
    title: str
    weight: int              # 3 = critical, 2 = important, 1 = nice to have
    status: str = "MISSING"  # VERIFIED | DECLARED | MISSING | UNRESOLVED
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
    tracks: list = field(default_factory=list)   # frameworks detected besides Claude Code settings


class Repo:
    def __init__(self, root: Path):
        self.root = root
        self._real_root = root.resolve()
        self._files = None

    def files(self):
        """Walk the tree once (skipping vendored and build folders); every pattern match reuses this list."""
        if self._files is None:
            out = []
            for dp, dns, fns in os.walk(self.root):
                dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".") or d in (".claude", ".github", ".devcontainer")]
                out += [Path(dp) / f for f in fns if self._readable(Path(dp) / f)]
                if len(out) > MAX_FILES:
                    break
            self._files = out
            self._rel = [p.relative_to(self.root).as_posix() for p in out]
        return self._files

    def _readable(self, p: Path) -> bool:
        """Never a secret-looking file, and never a file whose real path leaves the audited tree: the real path is
        resolved for every read (a linked file, or a linked folder anywhere on the way such as `.claude -> ../x`), so
        a guard or setting that lives elsewhere is not read (and earns nothing)."""
        if SECRET_FILE.match(p.name):
            return False
        try:
            real = p.resolve()
        except (OSError, RuntimeError):
            return False
        return real.is_relative_to(self._real_root) and not SECRET_FILE.match(real.name)

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
        if not p or not p.is_file() or not self._readable(p) or p.stat().st_size > MAX_FILE_BYTES:
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


# ------------------------------------------------------------------ framework tracks (1.4.1)
# Mirrors the "detect" signatures in kit/tracks/*/harness_track.json (tests keep the two in sync). Claude Code is
# read from .claude/settings*.json as before. A repo matches a track when a non-test file matching the glob
# contains the string. Detection and analysis are static: files are read and parsed with ast, never imported or run.
TRACK_SIGNATURES = {
    "agno": {"name": "Agno", "support": "assess-only", "detect": [["**/*.py", "from agno"], ["requirements*.txt", "agno"]]},
    "claude-agent-sdk": {"name": "Claude Agent SDK", "support": "full", "detect": [["**/*.py", "claude_agent_sdk"], ["requirements*.txt", "claude-agent-sdk"], ["pyproject.toml", "claude-agent-sdk"]]},
    "crewai": {"name": "CrewAI", "support": "full", "detect": [["**/*.py", "from crewai"], ["requirements*.txt", "crewai"], ["pyproject.toml", "crewai"]]},
    "dspy": {"name": "DSPy", "support": "assess-only", "detect": [["**/*.py", "import dspy"], ["requirements*.txt", "dspy"]]},
    "google-adk": {"name": "Google ADK", "support": "full", "detect": [["**/*.py", "google.adk"], ["requirements*.txt", "google-adk"], ["pyproject.toml", "google-adk"]]},
    "haystack": {"name": "Haystack", "support": "assess-only", "detect": [["**/*.py", "from haystack"], ["requirements*.txt", "haystack-ai"]]},
    "langgraph": {"name": "LangGraph", "support": "full", "detect": [["**/*.py", "from langgraph"], ["**/*.py", "from langchain.agents import create_agent"], ["requirements*.txt", "langgraph"], ["pyproject.toml", "langgraph"]]},
    "llamaindex": {"name": "LlamaIndex agents", "support": "assess-only", "detect": [["**/*.py", "from llama_index"], ["requirements*.txt", "llama-index"]]},
    "mastra": {"name": "Mastra", "support": "assess-only", "detect": [["package.json", "@mastra/core"], ["**/*.ts", "@mastra/core"]]},
    "microsoft-agent-framework": {"name": "Microsoft Agent Framework", "support": "full", "detect": [["**/*.py", "from agent_framework"], ["requirements*.txt", "agent-framework"], ["pyproject.toml", "agent-framework"]]},
    "openai-agents-sdk": {"name": "OpenAI Agents SDK", "support": "full", "detect": [["**/*.py", "from agents import"], ["requirements*.txt", "openai-agents"], ["pyproject.toml", "openai-agents"]]},
    "pydantic-ai": {"name": "Pydantic AI", "support": "assess-only", "detect": [["**/*.py", "from pydantic_ai"], ["requirements*.txt", "pydantic-ai"], ["pyproject.toml", "pydantic-ai"]]},
    "smolagents": {"name": "smolagents (Hugging Face)", "support": "assess-only", "detect": [["**/*.py", "from smolagents"], ["requirements*.txt", "smolagents"]]},
    "strands-agents": {"name": "AWS Strands Agents", "support": "full", "detect": [["**/*.py", "from strands"], ["requirements*.txt", "strands-agents"], ["pyproject.toml", "strands-agents"]]},
    "vercel-ai-sdk": {"name": "Vercel AI SDK", "support": "assess-only", "detect": [["package.json", "\"ai\""], ["**/*.ts", "from 'ai'"], ["**/*.ts", "from \"ai\""]]},
}

# The framework's own mechanism, named in every fix.
GUARD_FIX = {
    "langgraph": ("Pass an explicit tool list to create_agent / create_react_agent (or a ToolNode) and keep shell, file-write, web and computer tools out of it; gate any you need with interrupt() or HumanInTheLoopMiddleware.",
                  "Keep file-read, shell, web and computer tools out of the list, or refuse .env/.pem/.key/.ssh/.aws inputs in middleware or a tool wrapper before the call runs.",
                  "Gate shell, file-write and computer tools with interrupt() / HumanInTheLoopMiddleware, or refuse git push / reset --hard / rm -rf before the call runs."),
    "openai-agents-sdk": ("Pass an explicit tools=[...] to Agent and leave LocalShellTool, ShellTool, ComputerTool and hosted web tools out; if you need one, set needs_approval=True or add a tool input guardrail.",
                          "Keep file-read, shell, web and computer tools out of tools=[...], or refuse .env/.pem/.key/.ssh/.aws in a tool input guardrail.",
                          "Set needs_approval=True on shell, file-write and computer tools, or refuse git push / reset --hard / rm -rf in a tool input guardrail."),
    "crewai": ("Pass an explicit tools=[...] to Agent; leave allow_code_execution off and CodeInterpreterTool, file-writer and scraping tools out, or block them in a before-tool-call hook (return False).",
               "Keep file-read, code, web and computer tools out, or return False from a before-tool-call hook for .env/.pem/.key/.ssh/.aws inputs.",
               "Return False from a before-tool-call hook for git push / reset --hard / rm -rf (Task human_input=True reviews the answer after tools run, so it is no gate)."),
    "strands-agents": ("Pass an explicit tools=[...] of your own @tool functions to Agent; leave strands_tools shell, python_repl, file_write, http_request and use_computer out, or cancel them in a BeforeToolCallEvent hook.",
                       "Keep file-read, shell, web and computer tools out, or set event.cancel_tool in a BeforeToolCallEvent hook for .env/.pem/.key/.ssh/.aws inputs.",
                       "Set event.cancel_tool in a BeforeToolCallEvent hook for git push / reset --hard / rm -rf and file writes outside the repo."),
    "google-adk": ("Pass an explicit tools=[...] to Agent and keep shell, file-write, web and computer tools out, or block them in before_tool_callback (return a dict).",
                   "Keep file-read, shell, web and computer tools out, or return a dict from before_tool_callback for .env/.pem/.key/.ssh/.aws inputs.",
                   "Return a dict from before_tool_callback for git push / reset --hard / rm -rf, or keep such tools out."),
    "microsoft-agent-framework": ("Pass an explicit tools=[...] to Agent / create_harness_agent and keep shell, file-write, web and computer tools out, or mark them @tool(approval_mode=\"always_require\").",
                                  "Keep file-read, shell, web and computer tools out, or refuse .env/.pem/.key/.ssh/.aws in function middleware.",
                                  "Mark destructive tools @tool(approval_mode=\"always_require\") or refuse git push / reset --hard / rm -rf in function middleware."),
    "claude-agent-sdk": ("Set allowed_tools=[...] explicitly; if it includes Bash, Write, Edit or WebFetch, add disallowed_tools or a PreToolUse hook that returns permissionDecision deny.",
                         "Add a PreToolUse hook that denies .env/.pem/.key/.ssh/.aws paths for Read, Grep, Glob and Bash.",
                         "Add disallowed_tools for Bash(git push *), Bash(git reset --hard *), Bash(rm -rf *), or deny them in a PreToolUse hook."),
}
CATEGORY_WORDS = {"shell": "shell or code execution", "write": "file-write anywhere", "fetch": "web fetch",
                  "computer": "computer use", "read": "file-read anywhere",
                  "irreversible": "a fixed irreversible action"}
def _is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    return any(p in ("tests", "test", "testing") for p in parts[:-1]) or parts[-1].startswith("test_") or parts[-1].endswith("_test.py")


def _imports(text: str) -> set:
    """Module names a Python file imports, read with ast (never imported or run)."""
    try:
        tree = ast.parse(text or "")
    except SyntaxError:
        return set()
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
            mods.add(n.module)
    return mods


def _signature_hit(path: Path, text: str, needle: str) -> bool:
    if path.suffix == ".py":   # Python: a real import of the module, not the word in a string or comment
        m = re.match(r"^(?:from|import)\s+([\w.]+)", needle)
        mod = m.group(1) if m else needle
        return any(x == mod or x.startswith(mod + ".") for x in _imports(text))
    if path.name.startswith("requirements") and path.suffix == ".txt":
        return bool(re.search(rf"^\s*{re.escape(needle)}(\[[^\]]*\])?\s*([=<>~!;#\s]|$)", text, re.M))
    return needle in text


def detect_tracks(r: "Repo") -> dict:
    """{track_id: [files that matched]} for non-Claude tracks, from the signatures above. Test files are ignored."""
    r.files()
    out = {}
    for tid, sig in TRACK_SIGNATURES.items():
        hits = []
        for pat, needle in sig["detect"]:
            for f in r.glob(pat):
                if _is_test_path(r.rel(f).replace(os.sep, "/")):
                    continue
                if _signature_hit(f, r.text(f), needle):
                    hits.append(f)
        if hits:
            out[tid] = list(dict.fromkeys(hits))
    return out


G1_CATS = {"shell", "write", "fetch", "computer", "irreversible"}   # broad or irreversible: every one needs a guard
G2_CATS = {"shell", "fetch", "computer", "read"}                    # can reach or send secrets
G3_CATS = {"shell", "write", "computer", "irreversible"}           # can destroy or change things irreversibly
SECRET_RX = r"(\.env\b|\.pem\b|\.ssh\b|\.aws\b|\.key\b|id_rsa|credentials)"
DESTRUCTIVE_RX = r"(git push|reset --hard|rm -rf)"
PATH_RX = r"(is_relative_to|relative_to\(|commonpath|startswith\(\s*(str\()?\s*(ROOT|REPO|repo|root|BASE|base|cwd))"
DECLARE_RX = {
    "G1": r"^\s*(#{1,6}\s+|[-*]\s+)?(tools|tool allow ?list|allowed tools|tool list)\b",
    "G2": r"^\s*(#{1,6}\s+|[-*]\s+)?secrets?\b",
    "G3": r"^\s*(#{1,6}\s+|[-*]\s+)?(destructive|irreversible)\b",
}
DECLARED_CREDIT = 0.5   # declared evidence earns half a check's weight; derived evidence earns all of it

# Framework tools that are broad by design (matched on the last name of what is placed in the tool list).
NATIVE_BROAD = [
    (r"^(ShellTool|LocalShellTool|BashTool|PythonREPLTool|PythonAstREPLTool|CodeInterpreterTool|python_repl|shell|CodeAgent|ShellExecTool)$", "shell"),
    (r"^(WriteFileTool|FileWriterTool|FileManagementToolkit|file_write|editor|ApplyPatchTool)$", "write"),
    (r"^(WebSearchTool|RequestsGetTool|RequestsPostTool|ScrapeWebsiteTool|http_request|FileSearchTool|HostedWebSearchTool)$", "fetch"),
    (r"^(ComputerTool|use_computer|computer)$", "computer"),
    (r"^(ReadFileTool|FileReadTool|file_read)$", "read"),
]
CLAUDE_TOOL_CATS = {"Bash": "shell", "Write": "write", "Edit": "write", "MultiEdit": "write", "NotebookEdit": "write",
                    "WebFetch": "fetch", "WebSearch": "fetch", "Read": "read", "Grep": "read", "Glob": "read"}
CLAUDE_BUILTINS = list(CLAUDE_TOOL_CATS)
SHELL_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
               "subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen", "os.execv", "os.execvp",
               "os.spawnl", "pty.spawn", "exec", "eval", "compile", "asyncio.create_subprocess_shell",
               "asyncio.create_subprocess_exec", "builtins.exec", "builtins.eval"}
WRITE_FUNCS = {"shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.move", "shutil.rmtree", "os.remove", "os.unlink",
               "os.rename", "os.replace", "os.rmdir", "os.removedirs", "os.makedirs", "os.mkdir"}
FETCH_HEADS = {"requests", "httpx", "aiohttp", "urllib3", "http", "socket", "ftplib", "smtplib"}
COMPUTER_HEADS = {"pyautogui", "pynput", "pywinauto", "playwright", "selenium"}
WRITE_ATTRS = {"write_text", "write_bytes", "unlink", "rmdir", "touch", "rename", "replace", "mkdir", "chmod"}
READ_ATTRS = {"read_text", "read_bytes"}
SAFE_HEADS = {"json", "re", "math", "datetime", "time", "logging", "typing", "textwrap", "shlex", "hashlib", "base64",
              "itertools", "collections", "functools", "string", "uuid", "random", "statistics", "decimal", "fractions",
              "dataclasses", "enum", "copy", "pprint", "operator", "html", "difflib", "fnmatch", "glob", "pathlib",
              "os.path", "asyncio"}
SAFE_CALLS = {"os.environ.get", "os.getenv", "os.getcwd", "pathlib.Path", "Path", "glob.glob",
              # path arithmetic and directory listing: names only, no file contents, no commands
              "os.path.expanduser", "os.path.join", "os.path.basename", "os.path.dirname", "os.path.abspath",
              "os.path.realpath", "os.path.normpath", "os.path.exists", "os.path.isfile", "os.path.isdir",
              "os.path.splitext", "os.walk", "os.listdir", "os.scandir", "fnmatch.fnmatch"}
TAINT_SKIP = {"self", "cls", "ctx", "context", "tool_context", "config", "run_context", "wrapper", "runtime", "state"}
_BUILTIN_SAFE = set(dir(builtins)) - {"open", "exec", "eval", "compile", "__import__", "input", "breakpoint"}
AGENT_CTORS = {"Agent", "LlmAgent", "ChatAgent", "create_agent", "create_react_agent", "create_harness_agent",
               "ClaudeAgentOptions"}
FRAMEWORK_OF = [("claude_agent_sdk", "claude-agent-sdk"), ("agent_framework", "microsoft-agent-framework"),
                ("google.adk", "google-adk"), ("langgraph", "langgraph"), ("langchain", "langgraph"),
                ("agents", "openai-agents-sdk"), ("crewai", "crewai"), ("strands", "strands-agents")]


def _dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _uses(node, names) -> bool:
    return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(node))


CLASSES = ("secret", "destructive", "path")


class Guard:
    """A guard on a capability: a person approves it, or code refuses it under a condition.

    A refusal covers a class (secret paths, destructive commands, writes outside the repo) only when it refuses every
    input of that class, on every path, for the scored tool. A refusal that covers a class only in part (narrower,
    conditional, behind a flag, inverted) records why in `partial`: it earns nothing and makes the check UNRESOLVED."""

    def __init__(self, kind, where, label, secret=False, destructive=False, path=False, unresolved="", tools=None,
                 partial=None):
        self.kind, self.where, self.label = kind, where, label          # kind: approval | refusal
        self.secret, self.destructive, self.path = secret, destructive, path
        self.unresolved = unresolved                                   # why its coverage can't be read
        self.tools = tools                                             # None = every tool of the agent
        self.partial = dict(partial or {})                             # class -> why it is covered only in part

    def _cls(self, c):
        return True if getattr(self, c) else (None if c in self.partial else False)

    def _wanted(self, cid, cat):
        return CLASSES if cid == "G1" else ("secret",) if cid == "G2" else \
            ("destructive", "path") if cat == "write" else ("destructive",)

    def covers(self, cid, cat):
        """True (covered), False (not covered) or None (the audit cannot prove it: see why())."""
        if self.unresolved:
            return None
        if self.kind == "approval":
            return True
        vals = [self._cls(c) for c in self._wanted(cid, cat)]
        return True if True in vals else (None if None in vals else False)

    def why(self, cid, cat):
        return self.unresolved or "; ".join(dict.fromkeys(self.partial[c] for c in self._wanted(cid, cat) if c in self.partial))

    def __repr__(self):
        return f"{self.label} at {self.where}"


class Module:
    """One parsed Python file. Read with ast only: never imported or run."""

    def __init__(self, idx, path: Path):
        self.idx, self.path = idx, path
        self.text = idx.r.text(path)
        self.rel = idx.r.rel(path)
        try:
            self.tree = ast.parse(self.text or "")
        except SyntaxError:
            self.tree = ast.parse("")
        self.alias, self.funcs, self.classes, self.assigns = {}, {}, {}, {}
        for n in self.tree.body:
            if isinstance(n, ast.Import):
                for a in n.names:
                    self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom) and n.module:
                base = ("." * n.level) + n.module
                for a in n.names:
                    self.alias[a.asname or a.name] = f"{base}.{a.name}"
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs[n.name] = n
            elif isinstance(n, ast.ClassDef):
                self.classes[n.name] = n
            elif isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        self.assigns[t.id] = n.value
        for n in ast.walk(self.tree):   # nested defs (e.g. inside a factory) are reachable by name too
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs.setdefault(n.name, n)

    def where(self, node) -> str:
        return f"{self.rel}:{getattr(node, 'lineno', 0)}"

    def full(self, node) -> str:
        """Dotted name with the first part resolved through this file's imports and aliases."""
        d = _dotted(node)
        if not d:
            return ""
        head, _, rest = d.partition(".")
        if head in self.alias:
            return self.alias[head] + ("." + rest if rest else "")
        return d

    def src(self, node) -> str:
        return ast.get_source_segment(self.text, node) or ""

    def framework(self):
        mods = set(self.alias.values())
        for prefix, tid in FRAMEWORK_OF:
            if any(m == prefix or m.startswith(prefix + ".") for m in mods):
                return tid
        return None


class Index:
    """Every non-test Python file of the repo, parsed on demand."""

    def __init__(self, r: "Repo"):
        self.r, self._mods = r, {}
        self.files = {}
        for f in r.files():
            rel = r.rel(f).replace(os.sep, "/")
            if f.suffix == ".py" and not _is_test_path(rel):
                self.files[rel] = f

    def module(self, path: Path) -> Module:
        if path not in self._mods:
            self._mods[path] = Module(self, path)
        return self._mods[path]

    def find(self, dotted: str, from_mod: Module):
        """Repo file for a module name (absolute or relative), or None for anything outside the repo."""
        level = len(dotted) - len(dotted.lstrip("."))
        name = dotted.lstrip(".").replace(".", "/")
        bases = []
        if level:
            base = Path(from_mod.rel).parent
            for _ in range(level - 1):
                base = base.parent
            bases.append(base.as_posix())
        else:
            bases += [Path(from_mod.rel).parent.as_posix(), ""]
        for b in bases:
            for cand in (f"{name}.py", f"{name}/__init__.py"):
                rel = (f"{b}/{cand}" if b not in ("", ".") else cand)
                if rel in self.files:
                    return self.module(self.files[rel])
        return None

    def resolve(self, mod: Module, node, depth=0):
        """('def', Module, FunctionDef) | ('class', Module, ClassDef) | ('value', Module, node) |
        ('external', dotted) | ('unknown', text) for a name used in `mod`."""
        if depth > 6:
            return ("unknown", _dotted(node))
        if isinstance(node, ast.Name):
            n = node.id
            if n in mod.funcs:
                return ("def", mod, mod.funcs[n])
            if n in mod.classes:
                return ("class", mod, mod.classes[n])
            if n in mod.assigns:
                return ("value", mod, mod.assigns[n])
            if n in mod.alias:
                return self.resolve_dotted(mod, mod.alias[n], depth + 1)
            return ("external" if n in _BUILTIN_SAFE else "unknown", n)
        if isinstance(node, ast.Attribute):
            return self.resolve_dotted(mod, mod.full(node), depth + 1)
        return ("unknown", mod.src(node)[:60])

    def resolve_dotted(self, mod: Module, dotted: str, depth=0):
        lead = len(dotted) - len(dotted.lstrip("."))
        parts = dotted.lstrip(".").split(".")
        for cut in range(len(parts), 0, -1):          # longest module prefix that is a repo file
            target = self.find("." * lead + ".".join(parts[:cut]), mod)
            if target is None:
                continue
            rest = parts[cut:]
            if not rest:
                return ("module", target)
            if len(rest) == 1:
                return self.resolve(target, ast.Name(id=rest[0]), depth + 1)
            return ("unknown", dotted)
        return ("external", dotted.lstrip("."))


class Reach:
    """What one tool can do: capability occurrences, each with the guards in front of it."""

    def __init__(self):
        self.caps = []          # [(cat, where, [Guard])]
        self.unresolved = []    # reasons the audit could not follow the tool
        self.fixed = []         # actions with a fixed target the model cannot change (listed, never hidden)

    def merge(self, other, extra_guards=()):
        self.caps += [(c, w, list(g) + list(extra_guards)) for c, w, g in other.caps]
        self.unresolved += other.unresolved
        self.fixed += other.fixed


def _taint(fn, tainted) -> set:
    """Names inside `fn` that carry its input (parameters and anything assigned from them)."""
    tainted = set(tainted)
    for _ in range(3):
        for n in ast.walk(fn):
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and n.value is not None and _uses(n.value, tainted):
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                    tainted |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)) and _uses(n.iter, tainted):
                tainted |= {x.id for x in ast.walk(n.target) if isinstance(x, ast.Name)}
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for item in n.items:
                    if item.optional_vars is not None and _uses(item.context_expr, tainted):
                        tainted |= {x.id for x in ast.walk(item.optional_vars) if isinstance(x, ast.Name)}
    return tainted


def _cover_text(idx: Index, mod: Module, test, fn=None):
    """Source of a guard condition with the local variables, constants and helpers it uses expanded.
    Returns (text, unresolved): unresolved names a call in the condition the audit cannot read."""
    text, unresolved, seen, seen_calls = mod.src(test), "", set(), set()
    local = {}
    if fn is not None:
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        local.setdefault(t.id, n.value)
    todo = [test]
    while todo:
        node = todo.pop()
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id not in seen:
                seen.add(n.id)
                if n.id in local:
                    text += " " + mod.src(local[n.id]); todo.append(local[n.id]); continue
                kind = idx.resolve(mod, n)
                if kind[0] in ("value", "def"):
                    text += " " + kind[1].src(kind[2])
                    if kind[1] is mod and len(seen) < 40:
                        todo.append(kind[2])     # a helper's own constants decide too (e.g. is_secret -> SECRET_PART)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id not in _BUILTIN_SAFE \
                    and n.func.id not in local and n.func.id not in seen_calls:
                seen_calls.add(n.func.id)
                kind = idx.resolve(mod, n.func)
                if kind[0] != "def" and not (kind[0] == "external" and kind[1].split(".")[0] in SAFE_HEADS):
                    unresolved = f"{mod.where(n)} {mod.full(n.func)}(...) decides, and the audit cannot read it"
    return text, unresolved


def _dnf(e, limit=32):
    """A condition as OR of AND-lists of (expr, negated). Negated or oversized parts stay whole."""
    if isinstance(e, ast.BoolOp) and isinstance(e.op, ast.Or):
        out = [c for v in e.values for c in _dnf(v, limit)]
    elif isinstance(e, ast.BoolOp) and isinstance(e.op, ast.And):
        out = [[]]
        for v in e.values:
            out = [a + b for a in out for b in _dnf(v, limit)]
            if len(out) > limit:
                return [[(e, False)]]
    else:
        out = [[(e, False)]]
    return out


def _is_name_expr(mod, e) -> bool:
    return bool(re.search(r"(tool_name|\.name|\[[\"']name[\"']\])\s*$", mod.src(e)))


def _const_value(idx, mod, e):
    """(True, value) for a literal or a module constant assigned once to a literal; (False, None) otherwise."""
    if isinstance(e, ast.Constant):
        return True, e.value
    if isinstance(e, ast.Name) and e.id in mod.assigns and isinstance(mod.assigns[e.id], ast.Constant):
        stores = [n for n in ast.walk(mod.tree) if isinstance(n, ast.Name) and n.id == e.id and isinstance(n.ctx, ast.Store)]
        rebound = any(isinstance(n, (ast.Global, ast.Nonlocal)) and e.id in n.names for n in ast.walk(mod.tree))
        if len(stores) == 1 and not rebound:
            return True, mod.assigns[e.id].value
    return False, None


def _conjunct(idx, mod, e, neg, fn, tainted):
    """Classify one AND-part of a refusing condition.
    ('const', bool) | ('name', {tools}) | ('test', {classes}, node) | ('presence', name) | ('inverted', text) |
    ('condition', text) | ('unresolved', why)"""
    while isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        e, neg = e.operand, not neg
    if isinstance(e, ast.Compare) and len(e.ops) == 1:
        op, right = e.ops[0], e.comparators[0]
        if isinstance(right, ast.Constant) and (right.value is None or isinstance(right.value, bool)) and \
                isinstance(op, (ast.Is, ast.IsNot, ast.Eq, ast.NotEq)):
            # x is not None / x == True keep x's meaning; x is None / x == False / x != True invert it
            same = isinstance(op, (ast.Is, ast.Eq)) == (right.value is True)
            return _conjunct(idx, mod, e.left, neg if same else not neg, fn, tainted)
    known, val = _const_value(idx, mod, e)
    if known:
        return ("const", bool(val) != neg)
    text = mod.src(e)[:60]
    if isinstance(e, ast.Compare) and len(e.ops) == 1 and isinstance(e.ops[0], (ast.Eq, ast.In, ast.NotEq, ast.NotIn)):
        left, right, op = e.left, e.comparators[0], e.ops[0]
        side = right if _is_name_expr(mod, left) else left if isinstance(op, (ast.Eq, ast.NotEq)) and _is_name_expr(mod, right) else None
        if side is not None:
            vals = [_const_str(idx, mod, x) for x in (side.elts if isinstance(side, (ast.Tuple, ast.List, ast.Set)) else [side])]
            if None in vals:
                return ("unresolved", f"{mod.where(e)} tool-name test {text} is not readable")
            if neg != isinstance(op, (ast.NotEq, ast.NotIn)):
                return ("condition", f"not {text}")
            return ("name", set(vals))
    if not _uses(e, tainted):
        return ("condition", text)
    if isinstance(e, (ast.Name, ast.Attribute)):
        return ("condition", f"not {text}") if neg else ("presence", _dotted(e))
    if isinstance(e, ast.Call) and _dotted(e.func) in ("any", "all") and e.args and \
            isinstance(e.args[0], (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
        comp = e.args[0]                   # any(test for x in ...) is an OR over x; look inside it
        if _dotted(e.func) == "all":
            return ("condition", f"{text} refuses only when every listed test holds")
        if any(g.ifs for g in comp.generators):
            return ("condition", f"{text} tests only the inputs its `if` keeps")
        if any(len(b) > 1 for b in _dnf(comp.elt)):
            return ("condition", f"{text} combines tests with `and`")
    cover, unresolved = _cover_text(idx, mod, e, fn)
    if unresolved:
        return ("unresolved", unresolved)
    classes = {c for c, rx in (("secret", SECRET_RX), ("destructive", DESTRUCTIVE_RX), ("path", PATH_RX)) if re.search(rx, cover)}
    if isinstance(e, ast.Compare) and len(e.ops) == 1:
        op, left, right = e.ops[0], e.left, e.comparators[0]
        exact = isinstance(op, (ast.Eq, ast.NotEq)) or (isinstance(op, (ast.In, ast.NotIn)) and _uses(left, tainted)
                                                        and isinstance(right, (ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Constant)))
        if exact and classes - {"path"}:
            return ("condition", f"{text} matches exact values only")
        if isinstance(op, (ast.NotIn, ast.NotEq)):
            neg = not neg
    if neg:   # "refuse unless inside the repo" is the natural form of a path test; any other inverted test is not proof
        return ("test", {"path"}, e) if classes == {"path"} else ("inverted", f"not {text}")
    return ("test", classes, e)


def _refusals_from_if(idx, mod, node: ast.If, label, fn=None, context=(), tainted=None):
    """Guards for one refusing `if`: one per OR-branch of its condition, combined with the conditions it sits under.
    A branch covers a class only when every part of it tests the tool's input for that class; anything else that must
    also hold (a flag, another class, a test the audit cannot read) makes that class partial, with the reason."""
    if tainted is None:
        tainted = _taint(fn, {a.arg for a in fn.args.args + fn.args.kwonlyargs}) if fn is not None else set()
    blocker = next((c for c in context if isinstance(c, str)), "")
    pre = []                               # enclosing conditions: an AND of their parts; an OR stays one part
    for t, n in (c for c in context if not isinstance(c, str)):
        branches = _dnf(t)
        pre += branches[0] if not n and len(branches) == 1 else [(t, n)]
    guards = []
    for branch in _dnf(node.test):
        parts = [_conjunct(idx, mod, e, n, fn, tainted) for e, n in pre + branch]
        if any(p[0] == "const" and not p[1] for p in parts):
            continue                       # this branch can never refuse
        parts = [p for p in parts if p[0] != "const"]
        names = [p[1] for p in parts if p[0] == "name"]
        tools = set.intersection(*names) if names else None
        if names and not tools:
            continue
        unres = next((p[1] for p in parts if p[0] == "unresolved"), "")
        tests = [p for p in parts if p[0] == "test"]
        others = [p[1] for p in parts if p[0] in ("condition", "inverted")]
        others += [p[1] for p in parts if p[0] == "presence" and not any(_uses(t[2], {p[1].split(".")[0]}) for t in tests)]
        if blocker:
            others.append(blocker)
        g = Guard("refusal", mod.where(node), label, unresolved=unres, tools=tools)
        if not tests and not others:       # refuses every call (of the named tools)
            g.secret = g.destructive = g.path = True
        for c in CLASSES:
            if tests and not others and all(c in t[1] for t in tests):
                setattr(g, c, True)
            elif any(c in t[1] for t in tests) or (others and not tests) or \
                    (any(p[0] == "inverted" for p in parts) and c != "path"):
                extra = [mod.src(t[2])[:50] for t in tests if c not in t[1]] + others
                g.partial[c] = f"{mod.where(node)} {label} refuses {c} input only when {' and '.join(extra[:3]) or 'other conditions'} also hold"
        guards.append(g)
    return guards


def _refusing_ifs(fn, kind, test_ok):
    """(If, context) for every refusing `if` in fn, with the conditions it sits under (and why it might not run).
    An earlier `if` that exits without refusing (e.g. `return None` for one tool) is a condition too."""
    out = []

    def walk(body, ctx):
        ctx = list(ctx)
        for st in body:
            if isinstance(st, ast.If):
                if _is_refusal_body(st.body, kind) and test_ok(st.test):
                    out.append((st, tuple(ctx)))
                walk(st.body, ctx + [(st.test, False)])
                walk(st.orelse, ctx + [(st.test, True)])
                if not _is_refusal_body(st.body, kind) and any(isinstance(x, (ast.Return, ast.Raise)) for x in st.body):
                    ctx.append((st.test, True))           # later code runs only when this test was false
            elif isinstance(st, (ast.With, ast.AsyncWith, ast.For, ast.AsyncFor)):
                walk(st.body, ctx)
            elif isinstance(st, ast.While):
                walk(st.body, ctx + [f"{getattr(st, 'lineno', 0)}: inside a while loop"])
            elif isinstance(st, (ast.Try,) + ((ast.TryStar,) if hasattr(ast, "TryStar") else ())):
                why = f"line {st.lineno}: inside try (an exception handler can skip the refusal)"
                walk(st.body, ctx + [why])
                for h in st.handlers:
                    walk(h.body, ctx + [why])
                walk(st.orelse + st.finalbody, ctx + [why])
            elif isinstance(st, ast.Match):
                for case in st.cases:
                    walk(case.body, ctx + [f"line {st.lineno}: inside a match case"])
    walk(fn.body, [])
    return out


def _is_refusal_body(body, kind) -> bool:
    for st in body:
        if kind == "early" and isinstance(st, (ast.Return, ast.Raise, ast.Continue)):
            return True
        if kind == "false" and isinstance(st, ast.Return) and isinstance(st.value, ast.Constant) and st.value.value is False:
            return True
        if kind == "dict" and isinstance(st, ast.Return) and isinstance(st.value, ast.Dict):
            return True
        if kind == "cancel" and isinstance(st, ast.Assign) and any(isinstance(t, ast.Attribute) and t.attr == "cancel_tool" for t in st.targets):
            return True
        if kind == "deny" and isinstance(st, ast.Return) and st.value is not None and "deny" in ast.dump(st.value):
            return True
    return False


def _local_aliases(mod: Module, fn) -> dict:
    """Names bound in fn (or at module level) to a module, function or object the audit can name:
    `runner = subprocess`, `go = subprocess.run`, `client = httpx.Client()`, `with open(p) as f`."""
    out = {}
    for name, value in mod.assigns.items():
        if isinstance(value, (ast.Name, ast.Attribute, ast.Call)):
            out.setdefault(name, value)
    local = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            local.setdefault(n.targets[0].id, n.value)
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if isinstance(item.optional_vars, ast.Name):
                    local.setdefault(item.optional_vars.id, item.context_expr)
    out.update(local)
    return out


def _full_name(mod: Module, aliases: dict, node, depth=0) -> str:
    """Dotted name of a callee with local and module aliases expanded (`runner.run` -> `subprocess.run`)."""
    d = _dotted(node)
    head, _, rest = d.partition(".")
    if depth < 4 and head in aliases and head not in mod.alias and isinstance(aliases[head], (ast.Name, ast.Attribute)):
        base = _full_name(mod, aliases, aliases[head], depth + 1)
        return base + ("." + rest if rest else "")
    return mod.full(node)


FIXED_ARG = {"shell": ("args", "cmd", "command"), "open": ("file", "path"), "fetch": ("url",), "write": ()}


def _fixed_text(idx, mod, call, kind):
    """The constant target of a call that receives none of the tool's input, or None when the audit cannot read it."""
    vals = list(call.args[:1]) if kind != "write" else list(call.args)
    vals += [k.value for k in call.keywords if k.arg in FIXED_ARG[kind]]
    if not vals:
        return ""
    out = []
    for v in vals:
        s = _const_str(idx, mod, v)
        if s is None:
            lst = _str_list(idx, mod, v)
            if lst is None:
                return None
            s = " ".join(lst)
        out.append(s)
    return " ".join(out)


def _capability(call, full, head, on_tainted):
    """The kind of thing a call does: shell | open | write | read | fetch | computer | None."""
    attr = call.func.attr if isinstance(call.func, ast.Attribute) else ""
    if head in COMPUTER_HEADS:
        return "computer"
    if full in SHELL_FUNCS or full.split(".")[-1] in ("system", "popen") and head == "os":
        return "shell"
    if full in ("open", "io.open", "builtins.open", "codecs.open", "os.open") or (attr == "open" and on_tainted):
        return "open"
    if on_tainted and attr in WRITE_ATTRS:
        return "write"
    if on_tainted and attr in READ_ATTRS:
        return "read"
    if full in WRITE_FUNCS:
        return "write"
    if head in FETCH_HEADS or full.startswith("urllib.request") or full.endswith("urlopen") or full.endswith("urlretrieve"):
        return "fetch"
    return None


def _is_data(node) -> bool:
    """A literal, a comprehension or a call of a pure builtin (dict(), str(), list(), ...)."""
    if isinstance(node, (ast.Constant, ast.JoinedStr, ast.List, ast.Dict, ast.Tuple, ast.Set, ast.ListComp, ast.DictComp,
                         ast.SetComp, ast.GeneratorExp, ast.BinOp, ast.Subscript)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in \
        {"dict", "list", "set", "tuple", "str", "bytes", "int", "float", "sorted", "reversed", "enumerate", "zip", "range", "frozenset"}


def function_reach(idx: Index, mod: Module, fn, tainted=None, depth=0) -> Reach:
    """Follow the data a tool receives into calls that run commands, write or read files, fetch or use a computer.
    A capability is never dropped silently: a call the audit cannot follow is UNRESOLVED, and a call with a fixed
    target is still classified (a fixed `git push` is irreversible; a fixed `git status` is listed, not hidden)."""
    reach = Reach()
    if tainted is None:
        tainted = {a.arg for a in fn.args.args + fn.args.kwonlyargs + ([fn.args.vararg] if fn.args.vararg else [])
                   + ([fn.args.kwarg] if fn.args.kwarg else [])} - TAINT_SKIP
    tainted = _taint(fn, tainted)
    aliases = _local_aliases(mod, fn)
    refusals = [(n.end_lineno or n.lineno, g)
                for n, ctx in _refusing_ifs(fn, "early", lambda t: _uses(t, tainted))
                for g in _refusals_from_if(idx, mod, n, "inline refusal (early return)", fn, ctx, tainted)]

    def before(line):
        return [g for end, g in refusals if end < line]   # a capability inside the refusing branch is not guarded by it

    def add(cat, node):
        if not any(c == cat and w == mod.where(node) for c, w, _ in reach.caps):
            reach.caps.append((cat, mod.where(node), before(node.lineno)))

    for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
        args = list(call.args) + [k.value for k in call.keywords]
        hit = any(_uses(a, tainted) for a in args)
        if not isinstance(call.func, (ast.Name, ast.Attribute)):
            if hit or _uses(call.func, tainted) or not isinstance(call.func, ast.Call) or \
                    _dotted(call.func) in ("getattr", "__import__", "importlib.import_module", "eval"):
                reach.unresolved.append(f"{mod.where(call)} {mod.src(call.func)[:40]}(...) is a computed call the audit cannot follow")
            continue
        full = _full_name(mod, aliases, call.func)
        head = full.split(".")[0]
        on_tainted = isinstance(call.func, ast.Attribute) and _uses(call.func.value, tainted)
        attr = call.func.attr if isinstance(call.func, ast.Attribute) else ""
        if attr and isinstance(call.func.value, ast.Call) and attr not in WRITE_ATTRS | READ_ATTRS | {"open"}:
            continue     # e.g. urlopen(url).read(): the inner call is the capability
        cap = _capability(call, full, head, on_tainted)
        if cap == "computer":
            add("computer", call); continue
        if not hit and not on_tainted:
            if cap is None:
                continue
            text = _fixed_text(idx, mod, call, "open" if cap == "read" else cap)
            if text is None:
                reach.unresolved.append(f"{mod.where(call)} {full}(...) acts on a target the audit cannot read")
            elif cap in ("shell", "write") and re.search(DESTRUCTIVE_RX, text):
                add("irreversible", call)
            elif cap in ("shell", "open", "read") and re.search(SECRET_RX, text):
                add("read", call)
            else:
                reach.fixed.append(f"{text or full} ({mod.where(call)})")
            continue
        if cap == "shell":
            add("shell", call)
        elif cap == "open":
            mode = (call.args[0] if call.args else None) if attr else (call.args[1] if len(call.args) > 1 else None)
            mode = mode or next((k.value for k in call.keywords if k.arg == "mode"), None)
            m = mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else ("w" if full == "os.open" else "r")
            add("write" if any(c in m for c in "wax+") else "read", call)
        elif cap:
            add(cap, call)
        elif isinstance(call.func, ast.Attribute) and not on_tainted and head not in mod.alias:
            bound = aliases.get(head)
            if bound is None and isinstance(call.func.value, (ast.Constant, ast.JoinedStr, ast.List, ast.Dict, ast.Tuple, ast.Set)):
                continue     # a method on a literal: "".join(...)
            origin = "" if bound is None or _is_data(bound) else _full_name(mod, aliases, bound.func if isinstance(bound, ast.Call) else bound)
            if bound is not None and (_is_data(bound) or origin.split(".")[0] in SAFE_HEADS or origin in _BUILTIN_SAFE
                                      or origin in SAFE_CALLS):
                continue     # a method on local data (a dict, a str, a compiled regex)
            if isinstance(bound, ast.Call):
                ocap = _capability(bound, origin, origin.split(".")[0], False)
                if ocap == "open":
                    continue     # a handle opened above: the open() call is the capability
                if ocap:
                    add(ocap, call); continue
            reach.unresolved.append(f"{mod.where(call)} {mod.src(call.func)[:40]}(...) receives the tool's input on an object the audit cannot follow")
        elif full in SAFE_CALLS or head in SAFE_HEADS or full in _BUILTIN_SAFE or on_tainted:
            continue
        else:
            kind = idx.resolve(mod, call.func)
            if kind[0] == "def" and depth < 4:
                callee_mod, callee = kind[1], kind[2]
                params = [a.arg for a in callee.args.args]
                passed = set()
                for i, a in enumerate(call.args):
                    if i < len(params) and _uses(a, tainted):
                        passed.add(params[i])
                for k in call.keywords:
                    if k.arg and _uses(k.value, tainted):
                        passed.add(k.arg)
                sub = function_reach(idx, callee_mod, callee, passed or set(params), depth + 1)
                reach.merge(sub, before(call.lineno))
            elif kind[0] == "external" and kind[1].split(".")[0] in SAFE_HEADS:
                continue
            else:
                reach.unresolved.append(f"{mod.where(call)} {full}(...) receives the tool's input and the audit cannot follow it")
    return reach


def _decorator_guards(idx, mod, fn):
    guards, name = [], fn.name
    for d in fn.decorator_list:
        if isinstance(d, ast.Call):
            for c in d.args[:1]:
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    name = c.value          # @tool("name") / SDK @tool("name", ...)
            for k in d.keywords:
                if k.arg == "needs_approval" and isinstance(k.value, ast.Constant) and k.value.value is True:
                    guards.append(Guard("approval", mod.where(k.value), "needs_approval=True"))
                if k.arg == "approval_mode" and isinstance(k.value, ast.Constant) and k.value.value == "always_require":
                    guards.append(Guard("approval", mod.where(k.value), 'approval_mode="always_require"'))
                if k.arg in ("tool_input_guardrails", "input_guardrails") and isinstance(k.value, (ast.List, ast.Tuple)):
                    for el in k.value.elts:
                        guards += _callable_guards(idx, mod, el, "tool input guardrail", ("early", "dict", "false", "deny"))
    return guards, name


def _callable_guards(idx, mod, node, label, kinds) -> list:
    """A guard given as a function or object: read every refusing condition, or mark it unresolved.
    Conditions that apply to every tool are combined into one guard (a hook that refuses secrets in one `if` and
    destructive commands in another covers both); conditions limited to named tools stay separate guards."""
    kind = idx.resolve(mod, node.func if isinstance(node, ast.Call) else node)
    if kind[0] != "def":
        return [Guard("refusal", mod.where(node), label, unresolved=f"{mod.where(node)} {mod.src(node)[:50]} is not followed by the audit")]
    gm, fn = kind[1], kind[2]
    tainted = _taint(fn, {a.arg for a in fn.args.args + fn.args.kwonlyargs} - {"self"})
    found = [g for k in kinds for n, ctx in _refusing_ifs(fn, k, lambda t: _uses(t, tainted))
             for g in _refusals_from_if(idx, gm, n, label, fn, ctx, tainted)]
    if not found:
        return [Guard("refusal", gm.where(fn), label, unresolved=f"{gm.where(fn)} {fn.name} never refuses a call that the audit can see")]
    return _combine(found, label)


def _combine(found, label):
    """Refusals that apply to every tool combine (one `if` for secrets and another for destructive commands cover
    both); each keeps only what it proved, so a narrow or conditional branch cannot lend its class to another.
    Refusals limited to named tools stay separate guards."""
    general = [g for g in found if g.tools is None]
    out = []
    if general:
        readable = [g for g in general if not g.unresolved]
        if readable:
            g = Guard("refusal", readable[0].where, label)
            for c in CLASSES:
                if any(getattr(x, c) for x in readable):
                    setattr(g, c, True)
                elif any(c in x.partial for x in readable):
                    g.partial[c] = next(x.partial[c] for x in readable if c in x.partial)
            out.append(g)
        else:
            out.append(general[0])
    return out + [g for g in found if g.tools is not None]


def _callable_guard(idx, mod, node, label, kinds):
    """The guard a callable gives every tool (the first guard when all are tool-specific)."""
    return _callable_guards(idx, mod, node, label, kinds)[0]


def tool_reach(idx: Index, mod: Module, el):
    """(name, Reach, [Guard]) for one entry of an agent's tool list."""
    reach = Reach()
    if isinstance(el, ast.Starred):
        reach.unresolved.append(f"{mod.where(el)} *{mod.src(el.value)} spreads a tool list the audit does not follow")
        return mod.src(el), reach, []
    label = mod.src(el)[:60]
    target = el.func if isinstance(el, ast.Call) else el
    last = _dotted(target).split(".")[-1]
    for rx, cat in NATIVE_BROAD:
        if re.match(rx, last):
            reach.caps.append((cat, mod.where(el), []))
            return last, reach, []
    kind = idx.resolve(mod, target)
    for _ in range(3):
        if kind[0] == "value" and isinstance(kind[2], (ast.Name, ast.Attribute, ast.Call)):
            nxt = kind[2].func if isinstance(kind[2], ast.Call) else kind[2]
            last = _dotted(nxt).split(".")[-1]
            for rx, cat in NATIVE_BROAD:
                if re.match(rx, last):
                    reach.caps.append((cat, mod.where(el), []))
                    return last, reach, []
            kind = idx.resolve(kind[1], nxt)
    if kind[0] == "def":
        fmod, fn = kind[1], kind[2]
        guards, name = _decorator_guards(idx, fmod, fn)
        reach.merge(function_reach(idx, fmod, fn))
        return name, reach, guards
    if kind[0] == "class":
        cmod, cls = kind[1], kind[2]
        meth = next((m for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and m.name in ("_run", "_arun", "run", "__call__", "forward", "invoke")), None)
        if meth:
            reach.merge(function_reach(idx, cmod, meth))
            return cls.name, reach, []
    reach.unresolved.append(f"{mod.where(el)} {label} ({kind[1] if len(kind) == 2 else kind[0]}) is not followed by the audit")
    return label, reach, []


def _tool_list(idx, mod, node):
    if isinstance(node, ast.Name):
        k = idx.resolve(mod, node)
        if k[0] == "value":
            return k[1], k[2]
    return mod, node


def _kw(call, name):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _agent_guards(idx: Index, mod: Module, call: ast.Call, track: str) -> list:
    guards = []
    if track == "langgraph":
        mw = _kw(call, "middleware")
        if mw is not None:
            lmod, lst = _tool_list(idx, mod, mw)
            for el in (lst.elts if isinstance(lst, (ast.List, ast.Tuple)) else [lst]):
                k = idx.resolve(lmod, el) if not isinstance(el, ast.Call) else ("value", lmod, el)
                if k[0] == "value" and isinstance(k[2], ast.Call) and _dotted(k[2].func).endswith("HumanInTheLoopMiddleware"):
                    io = _kw(k[2], "interrupt_on")
                    names = {kk.value for kk, vv in zip(io.keys, io.values)
                             if isinstance(kk, ast.Constant) and not (isinstance(vv, ast.Constant) and vv.value is False)} if isinstance(io, ast.Dict) else None
                    guards.append(Guard("approval", k[1].where(k[2]), "HumanInTheLoopMiddleware", tools=names))
                else:
                    guards.append(Guard("refusal", lmod.where(el), "middleware", unresolved=f"{lmod.where(el)} middleware {lmod.src(el)[:40]} is not read by the audit"))
        ib = _kw(call, "interrupt_before")
        if isinstance(ib, (ast.List, ast.Tuple)) and any(isinstance(e, ast.Constant) and e.value == "tools" for e in ib.elts):
            guards.append(Guard("approval", mod.where(ib), "interrupt_before=['tools']"))
    elif track == "strands-agents":
        hooks = _kw(call, "hooks")
        if hooks is not None:
            hmod, lst = _tool_list(idx, mod, hooks)
            for el in (lst.elts if isinstance(lst, (ast.List, ast.Tuple)) else [lst]):
                k = idx.resolve(hmod, el.func if isinstance(el, ast.Call) else el)
                if k[0] == "class":
                    cm, cls = k[1], k[2]
                    methods = {m.name: m for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
                    found = False
                    for c in (n for n in ast.walk(cls) if isinstance(n, ast.Call) and _dotted(n.func).endswith("add_callback")):
                        if c.args and _dotted(c.args[0]).endswith("BeforeToolCallEvent") and len(c.args) > 1:
                            mname = _dotted(c.args[1]).split(".")[-1]
                            m = methods.get(mname)
                            if m:
                                found = True
                                tainted = _taint(m, {a.arg for a in m.args.args + m.args.kwonlyargs} - {"self"})
                                found = [g for n, ctx in _refusing_ifs(m, "cancel", lambda t: _uses(t, tainted))
                                         for g in _refusals_from_if(idx, cm, n, "BeforeToolCallEvent cancel_tool", m, ctx, tainted)]
                                guards += _combine(found, "BeforeToolCallEvent cancel_tool") if found else \
                                    [Guard("refusal", cm.where(m), "hook", unresolved=f"{cm.where(m)} hook never cancels a call the audit can see")]
                    if not found:
                        guards.append(Guard("refusal", hmod.where(el), "hook provider", unresolved=f"{hmod.where(el)} hook provider registers no BeforeToolCallEvent callback the audit can read"))
                else:
                    guards.append(Guard("refusal", hmod.where(el), "hook", unresolved=f"{hmod.where(el)} hook {hmod.src(el)[:40]} is not followed"))
    elif track == "google-adk":
        cb = _kw(call, "before_tool_callback")
        if cb is not None:
            guards += _callable_guards(idx, mod, cb, "before_tool_callback", ("dict",))
    elif track == "microsoft-agent-framework":
        mw = _kw(call, "middleware")
        if mw is not None:
            mmod, lst = _tool_list(idx, mod, mw)
            for el in (lst.elts if isinstance(lst, (ast.List, ast.Tuple)) else [lst]):
                for g in _callable_guards(idx, mmod, el, "function middleware", ("early",)):
                    if g.unresolved and "never refuses" in g.unresolved:
                        continue   # an observing middleware (e.g. a trace) is not a guard and hides nothing
                    guards.append(g)
    elif track == "crewai":
        for n in mod.tree.body:   # hooks registered in this module apply to its agents
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and _dotted(n.value.func).endswith("register_before_tool_call_hook") and n.value.args:
                for g in _callable_guards(idx, mod, n.value.args[0], "before-tool-call hook", ("false",)):
                    if not (g.unresolved and "never refuses" in g.unresolved):
                        guards.append(g)
        me = _assigned_name(mod, call)
        for n in ast.walk(mod.tree):  # Task(agent=this_agent, human_input=True): a person reviews the final answer
            if isinstance(n, ast.Call) and _dotted(n.func).split(".")[-1] == "Task":
                hi, ag = _kw(n, "human_input"), _kw(n, "agent")
                if isinstance(hi, ast.Constant) and hi.value is True and me and isinstance(ag, ast.Name) and ag.id == me:
                    guards.append(Guard("refusal", mod.where(hi), "human_input=True", unresolved=(
                        f"{mod.where(hi)} Task human_input=True asks a person to review the task's final answer after the "
                        "agent's tools have run; it approves no tool call")))
    return guards


def _assigned_name(mod, call):
    """The variable an agent constructor is assigned to (`unsafe = Agent(...)`), or None."""
    for n in ast.walk(mod.tree):
        if isinstance(n, ast.Assign) and n.value is call and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            return n.targets[0].id
    return None


def _const_str(idx, mod, n, depth=0):
    """A string the audit can read: a literal, a module constant, or an f-string of those. None otherwise."""
    if depth > 4 or n is None:
        return None
    if isinstance(n, ast.Constant) and isinstance(n.value, str):
        return n.value
    if isinstance(n, ast.Name):
        k = idx.resolve(mod, n)
        return _const_str(idx, k[1], k[2], depth + 1) if k[0] == "value" else None
    if isinstance(n, ast.JoinedStr):
        parts = [_const_str(idx, mod, v.value if isinstance(v, ast.FormattedValue) else v, depth + 1) for v in n.values]
        return None if None in parts else "".join(parts)
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
        a, b = _const_str(idx, mod, n.left, depth + 1), _const_str(idx, mod, n.right, depth + 1)
        return None if a is None or b is None else a + b
    return None


def _str_list(idx, mod, n, depth=0):
    """A list of strings the audit can read (literals, module constants, list + list). None otherwise."""
    if depth > 4 or n is None:
        return None
    if isinstance(n, (ast.List, ast.Tuple)):
        out = []
        for e in n.elts:
            if isinstance(e, ast.Starred):
                sub = _str_list(idx, mod, e.value, depth + 1)
                if sub is None:
                    return None
                out += sub
            else:
                v = _const_str(idx, mod, e, depth + 1)
                if v is None:
                    return None
                out.append(v)
        return out
    if isinstance(n, ast.Name):
        k = idx.resolve(mod, n)
        return _str_list(idx, k[1], k[2], depth + 1) if k[0] == "value" else None
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
        a, b = _str_list(idx, mod, n.left, depth + 1), _str_list(idx, mod, n.right, depth + 1)
        return None if a is None or b is None else a + b
    return None


def _matches(pattern, name):
    try:
        return bool(re.fullmatch(pattern, name))
    except re.error:
        return pattern == name


def _unresolved_reach(why):
    r = Reach()
    r.unresolved.append(why)
    return r


def _sdk_agent(idx, mod, call):
    """Claude Agent SDK options: built-in tools by name, permission rules, hooks and in-process MCP tools."""
    tools_kw, allowed_kw = _kw(call, "tools"), _kw(call, "allowed_tools")
    strs = lambda n: _str_list(idx, mod, n)
    available = strs(tools_kw) if tools_kw is not None else list(CLAUDE_BUILTINS)
    if available is None:
        return [("tools", _unresolved_reach(f"{mod.where(call)} tools={mod.src(tools_kw)[:40]} is not a list the audit can read"), [])]
    allowed = strs(allowed_kw) if allowed_kw is not None else []
    if allowed is None:      # unknown auto-approvals: nothing can be assumed to need a person
        allowed = list(available)
    mode = _kw(call, "permission_mode")
    mode = mode.value if isinstance(mode, ast.Constant) else "default"
    deny_rules = strs(_kw(call, "disallowed_tools")) if _kw(call, "disallowed_tools") is not None else []
    if deny_rules is None:   # an unreadable deny list removes nothing and refuses nothing
        deny_rules = []
    hooks_kw = _kw(call, "hooks")
    hook_guards = []
    if isinstance(hooks_kw, ast.Dict):
        for k, v in zip(hooks_kw.keys, hooks_kw.values):
            if not (isinstance(k, ast.Constant) and k.value == "PreToolUse") or not isinstance(v, (ast.List, ast.Tuple)):
                continue
            for hm in v.elts:
                if not isinstance(hm, ast.Call):
                    continue
                matcher = _kw(hm, "matcher")
                pattern = ".*" if matcher is None or (isinstance(matcher, ast.Constant) and matcher.value is None) \
                    else _const_str(idx, mod, matcher)
                hl = _kw(hm, "hooks")
                for h in (hl.elts if isinstance(hl, (ast.List, ast.Tuple)) else []):
                    for g in _callable_guards(idx, mod, h, "PreToolUse deny hook", ("deny",)):
                        if g.unresolved and "never refuses" in g.unresolved:
                            continue
                        if pattern is None:
                            g = Guard("refusal", g.where, g.label, unresolved=f"{mod.where(matcher)} hook matcher {mod.src(matcher)[:40]} is not readable")
                        hook_guards.append((pattern or ".*", g))
    servers, server_problem = _sdk_servers(idx, mod, call)
    mcp = {f"mcp__{key}__{n}": impl for key, entries in servers.items() if isinstance(entries, dict) for n, impl in entries.items()}
    names = list(available) + list(mcp)
    for a in allowed:                  # an allowed MCP name the audit cannot bind to an attached implementation
        if a.startswith("mcp__") and a not in names and not (len(a.split("__")) == 2 or a.endswith("__*")):
            names.append(a)
    for key, entries in servers.items():
        if isinstance(entries, str) and not any(n.startswith(f"mcp__{key}__") for n in names):
            names.append(f"mcp__{key}__*")
    tools = []
    for name in names:
        base = name.split("(")[0]
        reach, guards = Reach(), []
        if any(d.split("(")[0] == base and d.split("(")[1:] in ([], ["*)"], ["**)"]) for d in deny_rules):
            continue     # removed entirely
        cat = CLAUDE_TOOL_CATS.get(base) or ("computer" if "computer" in base.lower() else None)
        if base.startswith("mcp__"):
            key = base.split("__")[1] if len(base.split("__")) > 2 else ""
            impl = mcp.get(base)
            if impl is not None:
                if isinstance(impl, str):
                    reach.unresolved.append(impl)
                else:
                    reach.merge(function_reach(idx, impl[0], impl[1]))
            elif isinstance(servers.get(key), str):
                reach.unresolved.append(servers[key])
            elif server_problem:
                reach.unresolved.append(server_problem)
            elif key in servers:
                continue     # the configured server has no such tool: nothing to run
            else:
                reach.unresolved.append(f"{mod.where(call)} {base}: server {key!r} is not in mcp_servers here "
                                        "(it may come from settings or .mcp.json, which the audit does not bind)")
        elif cat:
            reach.caps.append((cat, mod.where(call), []))
        server_wide = any(a in (f"mcp__{base.split('__')[1]}", f"mcp__{base.split('__')[1]}__*") for a in allowed) \
            if base.startswith("mcp__") and len(base.split("__")) > 1 else False
        # any allow rule for the tool auto-approves at least part of it, so no approval can be assumed
        auto = base in allowed or name in allowed or any(x.split("(")[0] == base for x in allowed) or server_wide \
            or mode == "bypassPermissions" \
            or (mode == "acceptEdits" and cat == "write") or cat == "read"
        if not auto:
            guards.append(Guard("approval", mod.where(call), f"{base} not in allowed_tools (a person approves)"))
        for d in deny_rules:       # the same scope standard as Claude Code settings: a scoped rule covers its scope
            if d.split("(")[0] == base and "(" in d:
                guards.append(_rule_guard(d, "disallowed_tools", mod.where(call)))
        for pattern, g in hook_guards:      # the matcher picks the tools; a name test inside the hook narrows further
            if _matches(pattern, base) and (g.tools is None or base in g.tools):
                guards.append(g)
        tools.append((base, reach, guards))
    return tools


def _sdk_servers(idx, mod, call):
    """In-process MCP servers attached to these options: ({key: {tool name: (Module, FunctionDef) | why}} or
    {key: why}, problem). Only tools passed to create_sdk_mcp_server(tools=[...]) of a server in mcp_servers count."""
    ms = _kw(call, "mcp_servers")
    if ms is None:
        return {}, ""
    smod, d = _tool_list(idx, mod, ms)
    if not isinstance(d, ast.Dict) or None in d.keys:
        return {}, f"{mod.where(ms)} mcp_servers={mod.src(ms)[:40]} is not a dict the audit can read"
    out = {}
    for k, v in zip(d.keys, d.values):
        key = _const_str(idx, smod, k)
        if key is None:
            return {}, f"{smod.where(k)} an mcp_servers key is not readable"
        vmod, val = smod, v
        if isinstance(v, ast.Name):
            r = idx.resolve(smod, v)
            vmod, val = (r[1], r[2]) if r[0] == "value" else (smod, None)
        if not (isinstance(val, ast.Call) and _dotted(val.func).endswith("create_sdk_mcp_server")):
            out[key] = f"{smod.where(v)} MCP server {key!r} is not an in-process create_sdk_mcp_server(...) the audit can read"
            continue
        tl = _kw(val, "tools")
        lmod, lst = _tool_list(idx, vmod, tl) if tl is not None else (vmod, ast.List(elts=[]))
        if not isinstance(lst, (ast.List, ast.Tuple)):
            out[key] = f"{vmod.where(val)} tools of MCP server {key!r} are not a list the audit can read"
            continue
        entries = {}
        for el in lst.elts:
            r = idx.resolve(lmod, el)
            if r[0] != "def":
                entries[f"?{lmod.src(el)[:30]}"] = f"{lmod.where(el)} {lmod.src(el)[:40]} on MCP server {key!r} is not followed by the audit"
                continue
            fmod, fn = r[1], r[2]
            tname = next((dd.args[0].value for dd in fn.decorator_list if isinstance(dd, ast.Call) and dd.args
                          and isinstance(dd.args[0], ast.Constant) and isinstance(dd.args[0].value, str)), fn.name)
            entries[tname] = (fmod, fn)
        if any(n.startswith("?") for n in entries):
            out[key] = next(v for n, v in entries.items() if n.startswith("?"))
        else:
            out[key] = entries
    return out, ""


def find_agents(idx: Index, tid: str, files) -> list:
    """Agents of one framework: (label, where, [(tool name, Reach, [Guard])], [agent Guard], problem)."""
    agents = []
    for f in files:
        if f.suffix != ".py":
            continue
        mod = idx.module(f)
        if mod.framework() != tid:
            continue
        for call in (n for n in ast.walk(mod.tree) if isinstance(n, ast.Call)):
            ctor = mod.full(call.func)
            last = ctor.split(".")[-1]
            if last not in AGENT_CTORS:
                continue
            fw = next((t for p, t in FRAMEWORK_OF if ctor == p or ctor.startswith(p + ".")), mod.framework())
            if fw != tid:
                continue
            label = next((k.value.value for k in call.keywords if k.arg in ("name", "role") and isinstance(k.value, ast.Constant)), last)
            if tid == "claude-agent-sdk":
                if last != "ClaudeAgentOptions":
                    continue
                agents.append((label, mod.where(call), _sdk_agent(idx, mod, call), [], ""))
                continue
            tl = _kw(call, "tools")
            if tl is None and last in ("create_agent", "create_react_agent") and len(call.args) > 1:
                tl = call.args[1]
            tools, problem = [], ""
            if tl is None:
                problem = "" if tid == "crewai" or last == "ChatAgent" else ""
            else:
                lmod, lst = _tool_list(idx, mod, tl)
                if isinstance(lst, (ast.List, ast.Tuple)):
                    tools = [tool_reach(idx, lmod, el) for el in lst.elts]
                else:
                    problem = f"{mod.where(tl)} tool list {mod.src(tl)[:40]} is not a literal list the audit can read"
            for k in call.keywords:
                if k.arg == "allow_code_execution" and isinstance(k.value, ast.Constant) and k.value.value is True:
                    r_ = Reach(); r_.caps.append(("shell", mod.where(k.value), []))
                    tools.append(("allow_code_execution", r_, []))
            agents.append((label, mod.where(call), tools, _agent_guards(idx, mod, call, tid), problem))
    return agents


RANK = {"MISSING": 3, "UNRESOLVED": 2, "DECLARED": 1, "VERIFIED": 0}


def judge_agent(agent) -> dict:
    """G1-G3 for one agent, by the same rule on every framework."""
    label, where, tools, aguards, problem = agent
    out = {}
    for cid, cats in (("G1", G1_CATS), ("G2", G2_CATS), ("G3", G3_CATS)):
        bad, unclear, good = [], [], []
        if problem:
            unclear.append(problem)
        for name, reach, tguards in tools:
            gs = list(tguards) + [g for g in aguards if g.tools is None or name in g.tools]
            approved = [g for g in gs if g.kind == "approval" and not g.unresolved]
            if reach.unresolved and not approved:
                unclear += reach.unresolved
            for cat, w, inline in reach.caps:
                if cat not in cats:
                    continue
                verdicts = [g.covers(cid, cat) for g in gs + inline]
                words = CATEGORY_WORDS[cat]
                if any(v is True for v in verdicts):
                    g = next(g for g, v in zip(gs + inline, verdicts) if v is True)
                    good.append(f"{name} ({words}) at {w} guarded by {g.label} {g.where}")
                elif any(v is None for v in verdicts):
                    g = next(g for g, v in zip(gs + inline, verdicts) if v is None)
                    unclear.append(f"{name} ({words}) at {w}: {g.why(cid, cat)}")
                else:
                    bad.append(f"{name} ({words}) at {w} has no guard that " +
                               {"G1": "refuses or approves it", "G2": "keeps secrets out", "G3": "stops destructive use"}[cid])
        head = f"{where} {label}"
        fixed = [f for _, reach, _ in tools for f in reach.fixed]
        note = f"; fixed actions the model cannot change: {', '.join(fixed[:3])}" if fixed else ""
        if bad:
            out[cid] = ("MISSING", f"{head}: " + "; ".join(bad[:4]))
        elif unclear:
            out[cid] = ("UNRESOLVED", f"{head}: " + "; ".join(unclear[:3]))
        elif good:
            out[cid] = ("VERIFIED", f"{head}: " + "; ".join(good[:4]) + note)
        else:
            names = ", ".join(n for n, _, _ in tools) or "no tools"
            out[cid] = ("VERIFIED", f"{head}: tools [{names}]; no " +
                        {"G1": "shell, file-write, web or computer capability",
                         "G2": "tool can read files, run commands, fetch URLs or use a computer",
                         "G3": "tool can run commands, write anywhere or use a computer"}[cid] + note)
    return out


def guard_results(idx: Index, tid: str, files) -> dict:
    """G1-G3 for a framework surface: every agent must pass; agents never share guards."""
    name = TRACK_SIGNATURES[tid]["name"]
    fixes = GUARD_FIX[tid]
    agents = find_agents(idx, tid, files)
    out = {}
    for i, cid in enumerate(("G1", "G2", "G3")):
        if not agents:
            out[cid] = ("MISSING", "", f"{name}: no agent with an explicit tool list found. {fixes[i]}")
            continue
        res = [judge_agent(a)[cid] for a in agents]
        st = max((s for s, _ in res), key=RANK.get)
        ev = "; ".join(e for _, e in res)
        out[cid] = (st, ev, f"{name}: {fixes[i]}" + (" Where the audit cannot follow a tool or guard, make it a plain function "
                                                     "in this repo or state it in docs/IMPACT.md." if st == "UNRESOLVED" else ""))
    return out


def _rule_guard(x, kind, where):
    """What one scoped permission rule proves: the same standard for Claude Code settings and Agent SDK
    disallowed_tools. A file rule covers secrets when its pattern names a secret anywhere in the tree (`**/.env*`,
    `~/.ssh/**`); a single path is narrower. A Bash rule covers a destructive command when it matches that command with
    any arguments (`git push *`), and secrets only when it matches them in any command (`*.env*`)."""
    tool, scope = x.split("(")[0], x.split("(", 1)[1][:-1] if "(" in x else ""
    g = Guard("refusal", where, f"{kind} {x}")
    if tool == "Bash":
        m = re.match(r"^\s*(git push|git reset --hard|rm -rf)\s*:?\s*\*$", scope)   # any arguments: needs the *
        if m:
            g.destructive = True
        elif re.search(DESTRUCTIVE_RX, scope):
            g.partial["destructive"] = f"{where} {kind} {x} matches only that exact form of the command"
        if re.search(SECRET_RX, scope):
            if scope.startswith("*"):
                g.secret = True
            else:
                g.partial["secret"] = f"{where} {kind} {x} covers secrets only in commands starting {scope.split('*')[0].strip()!r}"
    elif re.search(SECRET_RX, scope):
        if re.match(r"^(\./|/)?\*\*/", scope) or re.match(r"^~/\.(ssh|aws|gnupg|config/gcloud)\b", scope):
            g.secret = True
        else:
            g.partial["secret"] = f"{where} {kind} {x} covers only {scope}"
    return g


# ------------------------------------------------------------------ Claude Code settings (1.4.2)
def claude_results(r: "Repo", settings) -> dict:
    """G1-G3 from .claude/settings*.json by the same rule: each built-in tool is removed, gated or ungated."""
    perms, mode, sandbox_auto, sandbox_on = {"allow": [], "deny": [], "ask": []}, "default", False, False
    lines, problem = {}, ""
    for p in settings:
        if not r._readable(p):     # e.g. a link to a file outside the repo: its rules can't be proven from the repo
            problem = problem or f"{r.rel(p)} is a link out of the repo (or not readable), so its rules are not read"
            continue
        try:
            data = json.loads(r.text(p) or "{}")
        except json.JSONDecodeError:
            problem = problem or f"{r.rel(p)} is not valid JSON, so its rules are not read"
            continue
        pm = data.get("permissions", {}) or {}
        for k in perms:
            perms[k] += [x for x in pm.get(k, []) or [] if isinstance(x, str)]
        mode = pm.get("defaultMode", mode)
        sb = data.get("sandbox", {}) or {}
        sandbox_auto = sandbox_auto or bool(sb.get("enabled") and sb.get("autoAllowBashIfSandboxed"))
        sandbox_on = sandbox_on or bool(sb.get("enabled"))
        for i, line in enumerate(r.text(p).splitlines(), 1):
            lines.setdefault(line.strip().strip(",").strip('"'), f"{r.rel(p)}:{i}")

    first = f"{r.rel(settings[0])}:1" if settings else ""

    def at(rule):
        return lines.get(rule, first)

    def rules(kind, tool):
        return [x for x in perms[kind] if x.split("(")[0] == tool or (tool.startswith("mcp__") and x.startswith(tool))]

    whole = lambda x: "(" not in x or x.split("(", 1)[1].rstrip(")") in ("*", "**", "")
    meaningful = [x for x in perms["deny"] + perms["ask"] if x.split("(")[0] in CLAUDE_TOOL_CATS
                  and (whole(x) or any(getattr(_rule_guard(x, "deny", at(x)), c) for c in CLASSES))]
    computer = sorted({x.split("(")[0] for x in perms["allow"] + perms["ask"] if "computer" in x.lower()})
    tools = []
    for tool in CLAUDE_BUILTINS + computer:
        cat = CLAUDE_TOOL_CATS.get(tool, "computer")
        if any(whole(x) for x in rules("deny", tool)):
            continue
        guards = []
        whole_ask = [x for x in rules("ask", tool) if whole(x)]
        auto = cat == "read" or bool(rules("allow", tool)) or mode in ("bypassPermissions", "dontAsk") \
            or (mode == "acceptEdits" and cat == "write") or (tool == "Bash" and sandbox_auto)
        if whole_ask:     # ask outranks allow: a person approves every call
            guards.append(Guard("approval", at(whole_ask[0]), f"ask {whole_ask[0]}"))
        elif not auto:
            guards.append(Guard("approval", first, f"{tool} needs approval (not in allow, default mode)"))
        for kind in ("ask", "deny"):   # a scoped rule covers only its scope
            guards += [_rule_guard(x, kind, at(x)) for x in rules(kind, tool) if not whole(x)]
        if cat == "read" or (tool == "Bash" and sandbox_on):
            # Read deny rules also bind Grep and Glob, and the sandbox applies them to every command's file reads
            guards += [_rule_guard(x, "deny", at(x)) for x in rules("deny", "Read") if tool != "Read" and not whole(x)]
        reach = Reach()
        reach.caps.append((cat, at(rules("allow", tool)[0]) if rules("allow", tool) else first, []))
        tools.append((tool, reach, guards))
    res = judge_agent(("Claude Code", first, tools, [], problem))
    fixes = ("Add permissions.deny for secrets and destructive commands, and deny or ask for broad tools you allow (Bash, Write, WebFetch).",
             "Deny Read of .env*, *.pem, *.key, ~/.ssh/**, ~/.aws/** (it also binds Grep and Glob), and gate every allowed web or shell tool.",
             "Deny or require approval for git push, reset --hard, rm -rf, and for Write/Edit if you allow them.")
    out = {}
    for i, cid in enumerate(("G1", "G2", "G3")):
        st, ev = res[cid]
        if cid == "G1" and not meaningful and st == "VERIFIED":
            st, ev = "MISSING", f"{r.rel(settings[0])}: no deny or ask rule restricts a tool (an empty or missing deny list is no guard)"
        elif cid == "G1" and not meaningful:
            ev += f"; and no deny or ask rule restricts a tool"
        out[cid] = (st, ev, fixes[i])
    return out


def declared_results(r: "Repo", tid: str) -> dict:
    name = TRACK_SIGNATURES[tid]["name"]
    impact = r.first("docs/IMPACT.md", "IMPACT.md")
    out = {}
    what = {"G1": "the agent's tool list", "G2": "how secrets are kept out of the agent's reach",
            "G3": "how destructive actions are refused or approved"}
    for cid, rx in DECLARE_RX.items():
        hit = r.grep(impact, rx, re.I | re.M) if impact else ""
        fix = (f"{name} is assess-only: the audit can't parse its tool lists yet. State {what[cid]} in docs/IMPACT.md "
               f"(declared evidence earns half the points), or build on a supported (full) track.")
        out[cid] = ("DECLARED", f"declared, not derived: {hit}", fix) if hit else ("MISSING", "", fix)
    return out


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

    tracks = detect_tracks(r)
    code_files = list(dict.fromkeys(f for tid, fs in sorted(tracks.items()) if TRACK_SIGNATURES[tid]["support"] == "full"
                                    for f in fs if f.suffix == ".py"))

    def code_grep(pattern):
        """First match in the detected framework code ('' when no framework track is detected)."""
        return r.grep_any(code_files, pattern) if code_files else ""

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

    led = r.first(".harness/ledger.jsonl")
    hb = r.glob("**/harness.py")
    hb_hit = r.grep_any(hb, r"criteria_sha")
    add("S8", A, "Approved criteria are hash-bound to execution evidence (ledger + runner)", 2, bool(led) and bool(hb_hit),
        (r.rel(led) + " + " + hb_hit) if led and hb_hit else "",
        "Use a runner that records criteria fingerprints, logs and code fingerprint in a hash-chained ledger (harness approve / verify / check).",
        unresolved=bool(hb_hit) and not led)
    dec = r.first("DECISIONS.md", "docs/DECISIONS.md", "docs/decisions", "docs/adr", "adr") or next(iter(r.glob("**/DECISIONS.md", "**/decisions.md", "**/adr/*.md", "**/decisions/*.md")), None)
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
    verifier_code = "" if verifier else code_grep(r"(name|role|description)\s*=\s*[\"'][^\"']*(verif|review|evaluat)")
    add("V5", A, "An independent verifier (subagent or evaluator rubric) checks the work", 1, bool(verifier) or bool(verifier_code),
        r.rel(verifier) if verifier else verifier_code, "Add a read-only verifier agent that checks an item against done_when before it passes"
        + (" (in framework code: a second agent named verifier with read-only tools)." if code_files else "."))

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
    # G1-G3 are judged per agent surface: Claude Code settings (unchanged since 1.1) and every detected framework
    # track. A check passes only when every surface passes it. Declared evidence (assess-only tracks) earns half.
    claude_g = {}
    deny = r.grep_any(settings, r"\"deny\"")
    claude_g["G1"] = ("MISSING", deny, "Add .claude/settings.json permissions.deny for secrets and destructive commands.")
    claude_g["G2"] = ("MISSING", "", "Deny Read of .env*, *.pem, *.key, ~/.ssh/**, ~/.aws/**.")
    claude_g["G3"] = ("MISSING", "", "Deny or require approval for git push, reset --hard, rm -rf.")
    surfaces = []
    if settings:
        surfaces.append(("claude-code", claude_results(r, settings)))
    idx = Index(r)
    for tid in sorted(tracks):
        if TRACK_SIGNATURES[tid]["support"] == "full":
            surfaces.append((tid, guard_results(idx, tid, tracks[tid])))
        else:
            surfaces.append((tid, declared_results(r, tid)))
    titles = {"G1": ("Permission deny rules exist", 3), "G2": ("Secrets are denied to the agent (.env, keys, credential folders)", 3),
              "G3": ("Destructive commands are denied or gated (push, reset --hard, rm -rf)", 2)}
    if tracks:
        titles = {"G1": ("The agent's actions are bounded (deny rules or an explicit tool list, broad tools gated)", 3),
                  "G2": ("Secrets are out of the agent's reach (.env, keys, credential folders)", 3),
                  "G3": ("Destructive actions are denied or gated (push, reset --hard, rm -rf, writes anywhere)", 2)}
    for cid, (title, weight) in titles.items():
        if not surfaces:          # nothing detected: exactly the 1.1 behaviour
            st, ev, fx = claude_g[cid]
            add(cid, A, title, weight, st == "VERIFIED", ev, fx)
            continue
        res = [(tid, *g[cid]) for tid, g in surfaces]
        many = len(res) > 1
        ev = "; ".join((f"[{tid}] " if many else "") + e for tid, st_, e, _ in res if e)
        failing = [f for _, st_, _, f in res if st_ != "VERIFIED"]
        fx = " | ".join(failing) or (res[0][3] if not many else " | ".join(f for _, _, _, f in res))
        status = max((x[1] for x in res), key=RANK.get)
        c = Check(cid, A, title, weight, fix=fx)
        c.status, c.evidence = status, ev
        checks.append(c)
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
    evalset = r.glob("**/*.evalset.json", "**/*.test.json")
    eval_code = "" if (pf or evalset) else code_grep(r"\bevaluate_agent\(|AgentEvaluator|langsmith.*evaluate|\bevaluate\(")
    add("E1", A, "Behaviour evals for the agent (promptfoo, ADK eval sets, MAF evaluate_agent, …)", 2,
        bool(pf) or bool(evalset) or bool(eval_code),
        r.rel((pf or evalset)[0]) if (pf or evalset) else eval_code,
        "Add a small eval suite: refuses secrets, keeps its instructions, answers with evidence, refuses destructive actions.")
    rt = r.glob("**/redteam*.yaml", "**/red_team*.py", "**/redteam*.yml")
    rt_hit = r.grep_any(rt + pf, r"(redteam|red_team|owasp|jailbreak|prompt-injection)")
    add("E2", A, "Red-team suite (promptfoo redteam or DeepTeam), mapped to OWASP LLM / agentic", 2, bool(rt_hit), rt_hit,
        "Add a red-team run (promptfoo redteam or DeepTeam) covering prompt leakage, excessive agency and injection.")
    live = r.grep_any(r.glob("**/redteam_live.py"), r"canary")
    add("E4", A, "Red team exercises the real tool path (canaries, tool trace, egress log, action-based verdicts)", 2, bool(live), live,
        "Run attacks through the real agent command in a throwaway workspace with canary secrets; judge tool calls, egress and file changes, not text.")
    ci = r.grep_any(r.glob(".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml"), r"(promptfoo|deepteam|red.?team|eval)")
    add("E3", A, "Evals run in CI, not only by hand", 1, bool(ci), ci, "Run the eval suite in CI on every PR that touches prompts, tools or agent config.")

    # 7. Cost and context (beyond the course) --------------------------------------------------------
    A = "7 Cost and context"
    model_set = r.grep_any(settings, r"\"(model|effortLevel)\"") or code_grep(
        r"\b(MODEL|MODEL_ID|model|model_id)\s*=\s*(os\.environ\.get\([^,]+,\s*)?[\"'][\w.:/-]{3,}[\"']")
    add("C1", A, "Model and effort chosen once, at session start (pinned in settings)", 1, bool(model_set), model_set,
        "Set model (and effortLevel if needed) in settings; avoid mid-session switches, which rebuild the prompt cache."
        + (" In framework code, set the model id once where the agent is built." if code_files else ""))
    cheap = next((p for p in agent_files if re.search(r"^model:\s*haiku", r.text(p), re.M)), None) or next((p for p in agent_files if re.search(r"^model:\s*sonnet", r.text(p), re.M)), None)
    cheap_code = "" if cheap else code_grep(r"model(_id)?\s*=\s*[\"'][^\"']*(haiku|mini|flash|small|lite)")
    add("C2", A, "Cheap lookups routed to a smaller model (e.g. Explore on Haiku)", 1, bool(cheap) or bool(cheap_code),
        r.grep(cheap, r"^model:", re.M) if cheap else cheap_code, "Add a read-only Explore agent with model: haiku that returns file:line evidence"
        + (" (in framework code: a lookup agent built on a smaller model)." if code_files else "."))
    usage = r.grep_any([p for p in (progress, instr) if p] + r.glob(".claude/skills/*/SKILL.md"), r"(tokens? (per|used)|token usage|usage per|wall[- ]clock|/usage|cost per (item|task|run))")
    add("C3", A, "Usage (tokens / time) recorded per accepted item", 1, bool(usage), usage,
        "Record wall-clock time and tokens per accepted item, so you can measure the harness instead of guessing.")
    filt = r.grep_any(settings + r.glob(".claude/hooks/*", "hooks/hooks.json", "**/hooks/hooks.json"), r"(PreToolUse|filter|grep -A)")
    filt = filt or code_grep(r"splitlines\(\)\[-\d+:\]|\[-\d{2,6}:\]")
    add("C4", A, "Long tool output is filtered before the model sees it (hooks)", 1, bool(filt), filt,
        "Add a PreToolUse hook that shows only failing test output, with the full log on disk."
        + (" In framework code, have tools return only the tail or the failures, with the full log on disk." if code_files else ""))

    # score -----------------------------------------------------------------------------------------
    rep = Report(repo=str(root))
    rep.checks = [asdict(c) for c in checks]
    rep.tracks = sorted(tracks)
    total = sum(c.weight for c in checks)
    got = sum(c.weight * (1.0 if c.status == "VERIFIED" else DECLARED_CREDIT if c.status == "DECLARED" else 0) for c in checks)
    rep.score = round(100 * got / total) if total else 0
    rep.grade = "A" if rep.score >= 85 else "B" if rep.score >= 70 else "C" if rep.score >= 50 else "D"
    for c in checks:
        a = rep.areas.setdefault(c.area, {"verified": 0, "total": 0})
        a["total"] += 1
        a["verified"] += c.status == "VERIFIED"
    return rep


def render_text(rep: Report, color: bool) -> str:
    C = (lambda code, s: f"\033[{code}m{s}\033[0m") if color else (lambda code, s: s)
    mark = {"VERIFIED": C("32", "✓ VERIFIED  "), "DECLARED": C("34", "~ DECLARED  "), "MISSING": C("31", "✗ MISSING   "),
            "UNRESOLVED": C("33", "? UNRESOLVED")}
    out = [C("1", f"Harness audit · {rep.repo}")]
    if rep.tracks:
        out.append(f"Frameworks detected: {', '.join(rep.tracks)}")
    out.append("")
    area = None
    for c in rep.checks:
        if c["area"] != area:
            area = c["area"]
            a = rep.areas[area]
            out.append(C("36;1", f"{area}  ({a['verified']}/{a['total']})"))
        crit = C("31", " [critical]") if c["weight"] == 3 and c["status"] != "VERIFIED" else ""
        out.append(f"  {mark[c['status']]} {c['id']} {c['title']}{crit}")
        if c["status"] in ("VERIFIED", "DECLARED") and c["evidence"]:
            out.append(C("90", f"               {c['evidence']}"))
        if c["status"] not in ("VERIFIED",):
            if c["evidence"] and c["status"] != "DECLARED":
                out.append(C("90", f"               found: {c['evidence']}"))
            out.append(f"               fix: {c['fix']}")
    if any(c["status"] == "DECLARED" for c in rep.checks):
        out += ["", "DECLARED: taken from what the repo states (docs/IMPACT.md), not from its code; it earns half a check's weight."]
    out += ["", C("1", f"Score {rep.score}/100 · grade {rep.grade}"),
            "A pass means the harness piece exists in files, not that it works. Run your checks to prove that."]
    return "\n".join(out)


def render_md(rep: Report) -> str:
    out = [f"## Harness audit · score {rep.score}/100 (grade {rep.grade})", "", "| | Check | Evidence or fix |", "|---|---|---|"]
    for c in rep.checks:
        icon = {"VERIFIED": "✅", "DECLARED": "🟦", "MISSING": "❌", "UNRESOLVED": "❓"}[c["status"]]
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
