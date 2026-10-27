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
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

VERSION = "1.4.5"
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

    def data(self, p: Path | None):
        """The bytes of a readable file inside the tree, or None."""
        if not p or not p.is_file() or not self._readable(p) or p.stat().st_size > MAX_FILE_BYTES:
            return None
        try:
            return p.read_bytes()
        except OSError:
            return None

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
        self.subject = None                                            # an inline refusal: the parameter it tests

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

    def tampered(self) -> set:
        """What some repo file rewrites at run time: the paths of repo modules whose names are replaced (an attribute
        store, setattr or delattr on a module, function, class or constant of theirs; globals(), vars(), locals(),
        exec or eval in the module itself), and the external modules patched the same way (`builtins`, `re`, ...)."""
        if getattr(self, "_tampered", None) is None:
            self._tampered = set()
            for dp, dns, fns in os.walk(self.r.root):          # every folder, skipped ones too: names only
                for fn in fns:
                    if fn in ("sitecustomize.py", "usercustomize.py") or fn.endswith(".pth"):
                        self._tampered.add("*")             # runs at interpreter start, before any guard
            for rel in list(self.files) + list(self.test_files()):
                m = self.module(self.files.get(rel) or self._test_files[rel])
                for n in ast.walk(m.tree):
                    target = None
                    if isinstance(n, (ast.Attribute, ast.Subscript)) and isinstance(n.ctx, (ast.Store, ast.Del)):
                        target = n.value
                    elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                        if n.func.id in ("setattr", "delattr") and n.args:
                            target = n.args[0]
                        elif n.func.id in ("globals", "vars", "locals", "exec", "eval", "__import__"):
                            self._tampered.add(m.path)
                    elif isinstance(n, ast.Name) and n.id == "__builtins__":
                        self._tampered.add("builtins")
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                        recv = ast.dump(n.func.value)
                        if n.func.attr in MUTATORS and ("'__dict__'" in recv or "'modules'" in recv):
                            self._tampered.add("*")          # x.__dict__.update(...), sys.modules.pop(...)
                        elif m.full(n.func) in ("importlib.reload", "imp.reload"):
                            self._tampered.add("*")
                    while isinstance(target, (ast.Attribute, ast.Subscript)):
                        target = target.value
                    if isinstance(target, ast.Call) and isinstance(target.func, ast.Name) and \
                            target.func.id in ("globals", "vars", "locals"):
                        self._tampered.add(m.path)
                    elif isinstance(target, ast.Call) or (isinstance(target, ast.Name) and target.id in m.alias and
                                                          m.alias[target.id].split(".")[0] in ("sys", "importlib", "builtins")):
                        self._tampered.add("*")     # sys.modules[...].x = ..., import_module(...).x = ...: any module
                    elif isinstance(target, ast.Name):
                        k = self.resolve(m, target)
                        if k[0] == "module":
                            self._tampered.add(k[1].path)
                        elif k[0] in ("def", "class", "value"):
                            self._tampered.add(k[1].path)
                        elif k[0] == "external" and target.id in m.alias:
                            self._tampered.add(k[1].split(".")[0])
        return self._tampered

    def test_files(self) -> dict:
        """Test-named Python files that a non-test module imports: never scored as agents, but once imported they
        can change modules at run time. A test file nothing imports runs only under the test runner."""
        if getattr(self, "_test_files", None) is None:
            self._test_files = {}
            tests = {}
            for f in self.r.files():
                rel = self.r.rel(f).replace(os.sep, "/")
                if f.suffix == ".py" and _is_test_path(rel):
                    tests[rel] = f
            todo = [self.module(self.files[rel]) for rel in self.files]
            seen = set()
            while todo:
                m = todo.pop()
                for n in ast.walk(m.tree):
                    names = [a.name for a in n.names] if isinstance(n, ast.Import) else \
                        [("." * n.level) + (n.module or "")] + [("." * n.level) + ((n.module + ".") if n.module else "") + a.name
                                                                for a in n.names] if isinstance(n, ast.ImportFrom) else []
                    for name in names:
                        rel = self._find_rel(name, m, tests)
                        if rel and rel not in seen:
                            seen.add(rel)
                            self._test_files[rel] = tests[rel]
                            todo.append(self.module(tests[rel]))
        return self._test_files

    def _find_rel(self, dotted, from_mod, files):
        level = len(dotted) - len(dotted.lstrip("."))
        name = dotted.lstrip(".").replace(".", "/")
        base = Path(from_mod.rel).parent
        for _ in range(max(level - 1, 0)):
            base = base.parent
        bases = [base.as_posix()] if level else [Path(from_mod.rel).parent.as_posix(), ""]
        for b in bases:
            for cand in (f"{name}.py", f"{name}/__init__.py"):
                rel = (f"{b}/{cand}" if b not in ("", ".") else cand)
                if rel in files:
                    return rel
        return None

    def helper_shadows(self) -> str:
        """F1: why `import kit_guard` may not load the pinned file: a kit_guard package or compiled module anywhere
        in the tree outside test folders (they win over a .py beside them), or a kit_guard.py whose bytes differ."""
        if getattr(self, "_helper_shadows", None) is None:
            self._helper_shadows = ""
            for dp, dns, fns in os.walk(self.r.root):
                rel = os.path.relpath(dp, self.r.root)
                if os.path.basename(dp) == "__pycache__" or _is_test_path(rel.replace(os.sep, "/") + "/x"):
                    continue           # test folders hold deliberately broken copies; they are not import roots
                for d in dns:
                    if d == KIT_GUARD_MODULE or d.startswith(KIT_GUARD_MODULE + "."):
                        self._helper_shadows = f"{os.path.join(rel, d)} is a kit_guard package that an import may load instead"
                for fn in fns:
                    if fn.split(".")[0] != KIT_GUARD_MODULE or fn.startswith(KIT_GUARD_MODULE + "_"):
                        continue
                    path = Path(dp) / fn
                    if fn != "kit_guard.py":
                        self._helper_shadows = f"{os.path.join(rel, fn)} is a compiled or other kit_guard module an import may load"
                    else:
                        data = self.r.data(path)
                        if data is None or hashlib.sha256(data).hexdigest() != KIT_GUARD_SHA256:
                            self._helper_shadows = f"{os.path.join(rel, fn)} is a kit_guard.py that is not the pinned helper"
                if self._helper_shadows:
                    return self._helper_shadows
        return self._helper_shadows

    def cancel_undo(self) -> str:
        """F5 (Strands): where some repo file sets cancel_tool to anything but a non-empty literal, deletes or
        augments it, or calls setattr or delattr with a computed or 'cancel_tool' name; '' when nowhere."""
        if getattr(self, "_cancel_undo", None) is None:
            self._cancel_undo = ""
            for rel in sorted(self.files):
                m = self.module(self.files[rel])
                for n in ast.walk(m.tree):
                    bad = None
                    if isinstance(n, ast.Attribute) and n.attr == "cancel_tool" and isinstance(n.ctx, (ast.Store, ast.Del)):
                        a = next((x for x in ast.walk(m.tree) if isinstance(x, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete))
                                  and any(t is n for t in (x.targets if isinstance(x, (ast.Assign, ast.Delete)) else [x.target]))), None)
                        ok = isinstance(a, ast.Assign) and isinstance(a.value, ast.Constant) and isinstance(a.value.value, str) \
                            and a.value.value.strip()
                        bad = None if ok else n
                    elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("setattr", "delattr") \
                            and len(n.args) > 1 and not (isinstance(n.args[1], ast.Constant) and n.args[1].value != "cancel_tool"):
                        bad = n
                    if bad is not None:
                        self._cancel_undo = (f"{m.where(bad)} cancel_tool may be set to something other than a message "
                                             "(or undone), so a cancel may not stand")
                        return self._cancel_undo
        return self._cancel_undo

    def crewai_hooks(self, home) -> str:
        """F5 (CrewAI): a before-tool-call hook registered anywhere but the top level of `home`, or ''."""
        for rel in sorted(self.files):
            m = self.module(self.files[rel])
            top = set(map(id, m.tree.body)) if m is home else set()
            for n in ast.walk(m.tree):
                reg = isinstance(n, ast.Call) and _dotted(n.func).split(".")[-1] in ("register_before_tool_call_hook",
                                                                                   "before_tool_call")
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    reg = any(_dotted(d.func if isinstance(d, ast.Call) else d).split(".")[-1] == "before_tool_call"
                              for d in n.decorator_list)
                    if reg:
                        return f"{m.where(n)} another before-tool-call hook is registered here and may change the input"
                    continue
                if reg and not (m is home and any(id(st) in top and st.value is n for st in m.tree.body
                                                  if isinstance(st, ast.Expr))):
                    return f"{m.where(n)} another before-tool-call hook is registered here and may change the input"
        return ""

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


# ------------------------------------------------------------------ canonical guard forms (1.4.5)
# The only code refusals the audit credits. The checker below implements exactly this list, `audit.py
# --canonical-forms` prints it, and the "Canonical guard forms" section of the audit's SKILL.md is this text (a test
# keeps them equal). Rounds 1 to 4 proved arbitrary Python control flow and each time the reviewer found neighbouring
# shapes, so 1.4.5 credits code refusals only through the kit's own guard helper in one exact call shape, or a
# framework's exact documented contract. Every other refusal is UNRESOLVED with the reason.
CANONICAL_FORMS = (
    ("F1 The kit helper",
     "Code refusals earn credit only through the kit's guard helper `kit/shared/kit_guard.py`, imported at module "
     "level exactly as `from kit_guard import refuses`, and only while that file's sha256 equals the pinned "
     "KIT_GUARD_SHA256. In the module, `refuses` is never rebound, shadowed (a parameter, local, def, class, loop or "
     "except name), reassigned, deleted, declared global or nonlocal, or imported again; `kit_guard` is imported "
     "nowhere else in the module (`import kit_guard`, an alias). Every kit_guard module in the tree outside test "
     "folders is that file: no kit_guard package, compiled kit_guard module or differing kit_guard.py. No repo file (a test file "
     "that a module imports included) "
     "changes the module, kit_guard, `builtins`, `re`, `shlex`, `fnmatch` or `urllib` at run time (globals(), "
     "setattr, an attribute store, `__dict__` or `sys.modules` methods, importlib.reload), and the tree has no "
     "sitecustomize.py, usercustomize.py or .pth file."),
    ("F2 Tool refusal",
     "The tool function's first statements (after its docstring) are `if refuses(P): return <literal>` or "
     "`if refuses(P): raise <built-in exception>(<literals>)`, with no else. P is the tool function's own parameter, "
     "and every other use of P in the function is the operation-bearing argument of a capability call: the command "
     "of a shell call (`subprocess.run(P, ...)`, `args=P`, `os.system(P)`), the file of `open(P, ...)`, the URL of a "
     "fetch (`requests.get(P)`, `urlopen(P)`, `url=P`). P is never aliased, reassigned, changed, sliced, "
     "field-selected, wrapped (`Path(P)`, `['sh', '-c', P]`), passed to any other function, or used as another "
     "argument (stdin, env). The capability call's other keyword arguments are literal options that cannot change "
     "what runs (shell, capture_output, text, check, timeout, encoding, errors, cwd; mode, newline, buffering for "
     "open; timeout, headers, redirects, verify for a fetch), its callee name is bound once, and no repo file "
     "patches its module. The tool has no decorator except the framework's own."),
    ("F3 Hook contracts",
     "A framework hook earns credit only when its first statements are `if refuses(INPUT): <refusal>` in the "
     "framework's documented contract, where INPUT is exactly the framework's tool input and <refusal> is its "
     "documented refusal. Google ADK before_tool_callback(tool, args, tool_context): INPUT `args`; refusal "
     "`return {<literal dict>}` (https://google.github.io/adk-docs/callbacks/types-of-callbacks/). CrewAI before-tool-"
     "call hook(ctx): INPUT `ctx.tool_input`; refusal `return False` (https://docs.crewai.com/en/learn/tool-hooks). "
     "Strands BeforeToolCallEvent callback(event): INPUT `event.tool_use` or `event.tool_use['input']`; refusal "
     "`event.cancel_tool = '<non-empty literal>'` on that same event parameter "
     "(https://strandsagents.com/latest/documentation/docs/user-guide/concepts/agents/hooks/). Microsoft Agent "
     "Framework function middleware(context, call_next): INPUT `context.arguments`; refusal `return`, `raise "
     "<built-in exception>(<literals>)`, or `context.result = <literal>` then `return` "
     "(https://learn.microsoft.com/en-us/agent-framework/user-guide/agents/agent-middleware). Claude Agent SDK "
     "PreToolUse hook(input_data, tool_use_id, context): INPUT `input_data['tool_input']` (or `.get('tool_input')`), "
     "or inside an F4 branch that names only tools executing it, one field: `['command']` (Bash) or `['file_path']` "
     "(Read, Write, Edit, MultiEdit); "
     "refusal: return, directly, the dict literal `{'hookSpecificOutput': {'hookEventName': 'PreToolUse', "
     "'permissionDecision': 'deny'[, 'permissionDecisionReason': '<literal>']}}` and nothing else "
     "(https://code.claude.com/docs/en/agent-sdk/hooks). Claude Agent SDK can_use_tool(tool_name, input_data, "
     "context): INPUT `input_data`; refusal `return PermissionResultDeny(message='<literal>')` "
     "(https://code.claude.com/docs/en/agent-sdk/permissions). OpenAI Agents SDK tool input guardrail(data): INPUT "
     "`data.context.tool_arguments`; refusal `return ToolGuardrailFunctionOutput.reject_content(<literals>)` or "
     "`.raise_exception(<literals>)` (https://openai.github.io/openai-agents-python/guardrails/). A refusal returned "
     "through a helper function, nested under other keys, or set on another object is not the contract."),
    ("F4 Tool scope (hooks only)",
     "A hook may limit its refusal to named tools with a top-level `if NAME == '<literal>':` (or `NAME in "
     "(<literals>)`) whose first statement is the F3 refusal. NAME is exactly the framework's field: `tool.name` "
     "(ADK), `ctx.tool_name` (CrewAI), `event.tool_use['name']` (Strands), `context.function.name` (Microsoft Agent "
     "Framework), `input_data['tool_name']` or `.get('tool_name')` (Claude Agent SDK hook), `tool_name` "
     "(can_use_tool). Several refusals and scoped branches may follow each other at the top; a scoped branch with "
     "anything after its refusal ends that run, and a refusal after any other statement earns nothing."),
    ("F5 The input stays as checked",
     "In the credited hook, outside the refusals and tool-name tests, and in every other hook, middleware or "
     "callback on the same agent and event, the hook's input parameters appear only as the sole argument of "
     "`copy.deepcopy`, `json.dumps`, `str` or `repr`, as a read (`.attr`, `['key']`, `.get('key')`) that is compared "
     "or tested, or (Microsoft Agent Framework) as the argument of the continuation call. They are never aliased, "
     "changed, or passed elsewhere. A Claude Agent SDK hook never returns `updatedInput` (every return is None, a dict "
     "literal with literal keys and no `updatedInput`, or a call of a module function whose returns are), and "
     "`can_use_tool`, when set, never passes `updated_input`. Strands: nothing in the repo sets `cancel_tool` to "
     "anything but a non-empty literal, deletes or augments it, or calls setattr or delattr with a computed name."),
    ("F6 Classes",
     "A credited refusal covers the two classes the helper defines, secret and destructive (kit_guard.py's docstring "
     "lists their members), for the calls it binds: in a tool, the capability calls whose operation argument is P "
     "(a delete such as shutil.rmtree(P) or Path(P).unlink() binds nothing); in a hook, the tools the hook and its "
     "scope apply to. There is no keyword rule: a hand-written test covers nothing. The helper reads text: it does "
     "not limit where a file-write tool writes."),
    ("F7 Everything else",
     "Any other code-level refusal, including hand-written predicates (`'.env' in command`, a regex, your own "
     "is_dangerous()), a helper refusal that is not first, or a refusal through another shape, is UNRESOLVED with "
     "the reason \"hand-written refusal: use the kit guard helper to earn credit\" or the rule it breaks. It earns "
     "no points; it does not count as missing either."),
)
KIT_GUARD_SHA256 = "263800b27043abba4be398b413af468308640f0be58f0186f247549f5119fc7f"   # kit/shared/kit_guard.py
KIT_GUARD_MODULE, KIT_GUARD_NAME = "kit_guard", "refuses"
KIT_GUARD_DEPS = ("builtins", "re", "shlex", "fnmatch", "urllib")
SDK_FIELD_TOOLS = {"command": {"Bash"}, "file_path": {"Read", "Write", "Edit", "MultiEdit"}}
HAND_WRITTEN = "hand-written refusal: use the kit guard helper to earn credit"
PURE_WRAPS = {"copy.deepcopy", "json.dumps", "str", "repr"}
# Per framework hook: where the tool input is and the tool's name (parameter index, attribute or key path), the
# continuation parameter, the refusal kind, and the parameters F5 restricts.
HOOK_SPECS = {
    "adk-hook": {"input": [(1, ())], "name": [(0, ("name",))], "refusal": "dict"},
    "crewai-hook": {"input": [(0, ("tool_input",))], "name": [(0, ("tool_name",))], "refusal": "false"},
    "strands-hook": {"input": [(0, ("tool_use",)), (0, ("tool_use", "input"))], "name": [(0, ("tool_use", "name"))],
                     "refusal": "cancel"},
    "maf-hook": {"input": [(0, ("arguments",))], "name": [(0, ("function", "name"))], "next": 1, "refusal": "maf"},
    "sdk-hook": {"input": [(0, ("tool_input",))], "name": [(0, ("tool_name",))], "refusal": "sdk-deny"},
    "sdk-permission": {"input": [(1, ())], "name": [(0, ())], "refusal": "sdk-permission"},
    "guardrail-hook": {"input": [(0, ("context", "tool_arguments"))], "name": [], "refusal": "guardrail"},
}
NESTED = {ast.For: "a for loop", ast.AsyncFor: "a for loop", ast.While: "a while loop", ast.With: "a with block",
          ast.AsyncWith: "a with block", ast.Try: "a try block", ast.FunctionDef: "a nested function",
          ast.AsyncFunctionDef: "a nested function", ast.If: "another if"}
for _name, _what in (("TryStar", "a try block"), ("Match", "a match statement")):
    if hasattr(ast, _name):
        NESTED[getattr(ast, _name)] = _what
BUILTIN_EXCEPTIONS = {n for n in dir(builtins) if isinstance(getattr(builtins, n), type)
                      and issubclass(getattr(builtins, n), BaseException)}


def canonical_forms_text() -> str:
    """The canonical forms as Markdown: what `--canonical-forms` prints and SKILL.md contains."""
    return "\n".join(f"- **{name}.** {text}" for name, text in CANONICAL_FORMS)


def _binds(tree, name, skip=()):
    """Every node in tree that binds `name`: assignments, deletions, imports (`as`), def and class names, `except ... as`,
    match captures, global and nonlocal declarations, and parameters (except the nodes in `skip`)."""
    out = []
    for n in ast.walk(tree):
        if n in skip:
            continue
        if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, (ast.Store, ast.Del)):
            out.append(n)
        elif isinstance(n, ast.alias) and (n.asname or n.name.split(".")[0]) == name:
            out.append(n)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name:
            out.append(n)
        elif isinstance(n, ast.ExceptHandler) and n.name == name:
            out.append(n)
        elif isinstance(n, (ast.Global, ast.Nonlocal)) and name in n.names:
            out.append(n)
        elif isinstance(n, ast.arg) and n.arg == name:
            out.append(n)
        elif type(n).__name__ in ("MatchAs", "MatchStar") and getattr(n, "name", None) == name:
            out.append(n)
        elif type(n).__name__ == "MatchMapping" and getattr(n, "rest", None) == name:
            out.append(n)
    return out


def _assigned_once(tree, name) -> bool:
    return len(_binds(tree, name)) == 1


def _const_value(idx, mod, e):
    """(True, value) for a literal or a module constant assigned once to a literal; (False, None) otherwise."""
    if isinstance(e, ast.Constant):
        return True, e.value
    if isinstance(e, ast.Name) and e.id in mod.assigns and isinstance(mod.assigns[e.id], ast.Constant) \
            and _assigned_once(mod.tree, e.id):
        return True, mod.assigns[e.id].value
    return False, None


def _lit(idx, mod, e):
    ok, val = _const_value(idx, mod, e)
    return val if ok and isinstance(val, str) else None


def _lits(idx, mod, e):
    """A string literal, or a tuple or list of them (inline or a module constant assigned once), as a tuple; else None."""
    if isinstance(e, ast.Name) and e.id in mod.assigns and isinstance(mod.assigns[e.id], (ast.Tuple, ast.List)) \
            and _assigned_once(mod.tree, e.id):
        e = mod.assigns[e.id]
    if isinstance(e, (ast.Tuple, ast.List)):
        out = tuple(_lit(idx, mod, x) for x in e.elts)
        return out if out and None not in out else None
    v = _lit(idx, mod, e)
    return (v,) if v is not None else None


def _literal(node) -> bool:
    """A Python literal (a constant, or a dict, list, tuple or set of them)."""
    try:
        ast.literal_eval(node)
        return True
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False


def _helper(idx, mod):
    """(name, '') when `mod` binds the pinned kit helper by F1, else (None, why)."""
    if getattr(mod, "_helper", None) is None:
        mod._helper = _helper_check(idx, mod)
    return mod._helper


def _helper_check(idx, mod):
    tops = [n for n in mod.tree.body if isinstance(n, ast.ImportFrom) and n.module == KIT_GUARD_MODULE and not n.level]
    others = [n for n in ast.walk(mod.tree) if isinstance(n, (ast.Import, ast.ImportFrom)) and n not in tops and (
        KIT_GUARD_MODULE in (getattr(n, "module", None) or "").split(".") or any(KIT_GUARD_MODULE in a.name.split(".") for a in n.names))]
    if not tops:
        return None, "the module does not import the kit helper as `from kit_guard import refuses`"
    if len(tops) > 1 or others:
        n = (tops[1:] + others)[0]
        return None, f"{mod.where(n)} kit_guard is imported more than once or under another name"
    imp = tops[0]
    if [(a.name, a.asname) for a in imp.names] != [(KIT_GUARD_NAME, None)]:
        return None, f"{mod.where(imp)} the import is not exactly `from kit_guard import refuses`"
    binds = _binds(mod.tree, KIT_GUARD_NAME)
    if binds != [imp.names[0]]:
        b = next(b for b in binds if b is not imp.names[0])
        return None, f"`{KIT_GUARD_NAME}` is rebound or shadowed at line {getattr(b, 'lineno', imp.lineno)}"
    target = idx.find(KIT_GUARD_MODULE, mod)
    if target is None or target.path.name != "kit_guard.py":
        return None, "kit_guard.py is not a file in this repo beside the module or at its root"
    data = idx.r.data(target.path)
    if data is None or hashlib.sha256(data).hexdigest() != KIT_GUARD_SHA256:
        return None, f"{target.rel} is not the shipped kit helper (its sha256 differs from the pinned one)"
    shadow = idx.helper_shadows()
    if shadow:
        return None, shadow
    tampered = idx.tampered()
    hit = next((t for t in (target.path, mod.path, "*") + KIT_GUARD_DEPS if t in tampered), None)
    if hit is not None:
        what = {target.path: target.rel, mod.path: mod.rel, "*": "a module reached through sys.modules or a call"}
        return None, f"{what.get(hit, f'the `{hit}` module')} is changed at run time somewhere in the repo"
    return KIT_GUARD_NAME, ""


def _is_kit_guard(idx, mod, func) -> bool:
    """A call of the pinned helper bound by F1 (the audit does not walk it as a capability)."""
    return isinstance(func, ast.Name) and _helper(idx, mod)[0] == func.id


FRAMEWORK_HEADS = {"claude_agent_sdk", "agent_framework", "google", "langgraph", "langchain", "langchain_core", "agents",
                   "crewai", "strands"}


def _decorated(idx, mod, fn):
    """Why a guard function's decorators may replace it, or '': only the frameworks' own decorators (and
    staticmethod or classmethod) leave the function as written."""
    for d in fn.decorator_list:
        k = idx.resolve(mod, d.func if isinstance(d, ast.Call) else d)
        if k[0] == "external" and (k[1].split(".")[0] in FRAMEWORK_HEADS or k[1] in ("staticmethod", "classmethod")):
            continue
        return f"{mod.where(d)} the decorator `{mod.src(d)[:40]}` may replace the function"
    return ""


def _chain(node):
    """(root name, [keys]) for P, P.attr, P['k'], P.get('k'[, literal]) chains; None otherwise."""
    keys = []
    while True:
        if isinstance(node, ast.Attribute):
            keys.append(node.attr); node = node.value
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            keys.append(node.slice.value); node = node.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" \
                and 1 <= len(node.args) <= 2 and not node.keywords and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str) and all(_literal(a) for a in node.args[1:]):
            keys.append(node.args[0].value); node = node.func.value
        elif isinstance(node, ast.Name):
            return node.id, keys[::-1]
        else:
            return None


MUTATORS = {"update", "clear", "pop", "popitem", "setdefault", "append", "extend", "insert", "remove", "sort",
            "reverse", "__setitem__", "__delitem__", "__setattr__"}


def _rebound(fn, name, path=()):
    """Where fn rebinds, deletes or declares global `name`, or changes in place the part of it at `path`, or None."""
    def keys(node):
        out = []
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            out.append(node.attr if isinstance(node, ast.Attribute) else
                       node.slice.value if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str) else "*")
            node = node.value
        return (out[::-1] if isinstance(node, ast.Name) and node.id == name else None)

    def overlaps(ks):
        return ks is not None and all(a == b or "*" in (a, b) for a, b in zip(ks, path))

    own = set(fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs +
              [a for a in (fn.args.vararg, fn.args.kwarg) if a is not None])
    found = _binds(fn, name, skip=own)
    if found:
        return found[0]
    for n in ast.walk(fn):
        if isinstance(n, (ast.Attribute, ast.Subscript)) and isinstance(n.ctx, (ast.Store, ast.Del)) and overlaps(keys(n)):
            return n
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in MUTATORS and overlaps(keys(n.func.value)):
            return n
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("setattr", "delattr") and n.args \
                and keys(n.args[0]) is not None:
            return n
    return None


def _parents(fn) -> dict:
    out = {}
    for p in ast.walk(fn):
        for c in ast.iter_child_nodes(p):
            out[c] = p
    return out


def _chain_top(node, parents):
    """The largest P.attr / P['k'] / P.get('k') expression that starts at the Name `node`."""
    top = node
    while True:
        p = parents.get(top)
        if isinstance(p, (ast.Attribute, ast.Subscript)) and p.value is top and _chain(p) is not None:
            top = p
        elif isinstance(p, ast.Attribute) and p.attr == "get" and isinstance(parents.get(p), ast.Call) \
                and parents[p].func is p and _chain(parents[p]) is not None:
            top = parents[p]
        else:
            return top


SAFE_KWARGS = {"shell": ("shell", "capture_output", "text", "check", "timeout", "encoding", "errors",
                          "universal_newlines", "cwd"),
               "read": ("mode", "encoding", "errors", "newline", "buffering"), "write": ("mode", "encoding", "errors", "newline", "buffering"),
               "fetch": ("timeout", "headers", "allow_redirects", "follow_redirects", "verify")}


def _op_arg(call, cat, full):
    """The argument that carries the operation (F2): the command of a shell call, the file of open(), the URL of a
    fetch; None for anything else (a path receiver such as Path(p).read_text(), a copy, a delete) or when `*`/`**`
    unpacking could supply it."""
    if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        return None
    name = full.split(".")[-1] if full else (call.func.attr if isinstance(call.func, ast.Attribute) else "")
    if cat == "shell":
        pos, kws = 0, ("args",) if full.startswith(("subprocess.", "asyncio.")) else ("command", "cmd")
    elif cat in ("read", "write", "open") and full in ("open", "io.open", "builtins.open", "codecs.open", "os.open"):
        pos, kws = 0, {"open": ("file",), "io.open": ("file",), "builtins.open": ("file",),
                       "codecs.open": ("filename",), "os.open": ("path",)}[full]
    elif cat == "fetch" and name in ("get", "post", "put", "patch", "delete", "head", "options", "request", "stream",
                                     "urlopen", "urlretrieve", "Request"):
        pos, kws = (1 if name in ("request", "stream") else 0), ("url",)
    else:
        return None
    safe = SAFE_KWARGS.get(cat if cat != "open" else "read", ())
    if any(k.arg not in kws and (k.arg not in safe or not _literal(k.value)) for k in call.keywords):
        return None                  # executable=, env=, preexec_fn=, input=, opener=, a computed shell=: not as written
    given = [k.value for k in call.keywords if k.arg in kws]
    if given:
        return given[0] if len(call.args) <= pos else None
    return call.args[pos] if len(call.args) > pos else None


class _Canon:
    """Reads one guard function (a tool or a hook) against CANONICAL_FORMS."""

    def __init__(self, idx, mod, fn, kinds, label, role):
        self.idx, self.mod, self.fn, self.kinds, self.label, self.role = idx, mod, fn, kinds, label, role
        self.params = [a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs if a.arg not in ("self", "cls")]
        self.inputs = _taint(fn, set(self.params) - (TAINT_SKIP if role == "tool" else set()))
        self.spec = HOOK_SPECS.get(role, {})
        at = lambda i: self.params[i] if i < len(self.params) else None
        self.input_paths = {(at(i), tuple(k)) for i, k in self.spec.get("input", [])}
        self.name_paths = {(at(i), tuple(k)) for i, k in self.spec.get("name", [])}
        self.restricted = {p for p, _ in self.input_paths | self.name_paths if p}
        self.next = at(self.spec["next"]) if "next" in self.spec else None
        self.helper, self.helper_why = _helper(idx, mod)
        self.blocked = _decorated(idx, mod, fn)
        if not self.blocked and mod.path in idx.tampered():
            self.blocked = f"{mod.rel} is changed at run time (globals(), setattr or an attribute store on its names)"
        self.parents = _parents(fn)
        self.allowed = set()            # Name nodes of restricted parameters used by credited statements

    # -- shapes
    def body(self):
        b = self.fn.body
        return b[1:] if b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant) \
            and isinstance(b[0].value.value, str) else b

    def helper_call(self, test):
        """The argument of `refuses(<one argument>)`, or None."""
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Name) and test.func.id == KIT_GUARD_NAME \
                and len(test.args) == 1 and not test.keywords and not isinstance(test.args[0], ast.Starred):
            return test.args[0]
        return None

    def refusal(self, body) -> bool:
        """F2/F3: the body is exactly the documented refusal."""
        kind = "early" if self.role == "tool" else self.spec.get("refusal")
        if kind in ("early", "maf"):
            if kind == "maf" and len(body) == 2 and isinstance(body[0], ast.Assign) and len(body[0].targets) == 1:
                t = body[0].targets[0]
                if isinstance(t, ast.Attribute) and t.attr == "result" and isinstance(t.value, ast.Name) and \
                        t.value.id == self.params[0] and _literal(body[0].value) and isinstance(body[1], ast.Return) \
                        and (body[1].value is None or (isinstance(body[1].value, ast.Constant) and body[1].value.value is None)):
                    self.allowed.add(t.value)
                    return True
            if len(body) != 1:
                return False
            st = body[0]
            if isinstance(st, ast.Return):
                return st.value is None or _literal(st.value)
            if isinstance(st, ast.Raise) and st.cause is None:
                e = st.exc
                call = e if isinstance(e, ast.Call) else None
                name = call.func if call else e
                return isinstance(name, ast.Name) and name.id in BUILTIN_EXCEPTIONS and not _binds(self.mod.tree, name.id) \
                    and (call is None or (all(_literal(a) for a in call.args) and all(k.arg and _literal(k.value) for k in call.keywords)))
            return False
        if len(body) != 1:
            if kind == "cancel" and len(body) == 2 and isinstance(body[1], ast.Return) and body[1].value is None:
                body = body[:1]
            else:
                return False
        st = body[0]
        if kind == "dict":
            return isinstance(st, ast.Return) and isinstance(st.value, ast.Dict) and bool(st.value.keys) and \
                None not in st.value.keys and _literal(st.value) and \
                len({k.value for k in st.value.keys}) == len(st.value.keys)
        if kind == "false":
            return isinstance(st, ast.Return) and isinstance(st.value, ast.Constant) and st.value.value is False
        if kind == "cancel":
            if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Attribute):
                t = st.targets[0]
                if t.attr == "cancel_tool" and isinstance(t.value, ast.Name) and self.params and t.value.id == self.params[0] \
                        and isinstance(st.value, ast.Constant) and isinstance(st.value.value, str) and st.value.value.strip():
                    self.allowed.add(t.value)
                    return True
            return False
        if kind == "sdk-deny":
            return isinstance(st, ast.Return) and _sdk_deny_literal(st.value)
        if kind == "sdk-permission":
            v = st.value if isinstance(st, ast.Return) else None
            return isinstance(v, ast.Call) and self.mod.full(v.func) == "claude_agent_sdk.PermissionResultDeny" and \
                not v.args and all(k.arg in ("message", "interrupt") and _literal(k.value) for k in v.keywords)
        if kind == "guardrail":
            v = st.value if isinstance(st, ast.Return) else None
            return isinstance(v, ast.Call) and self.mod.full(v.func) in (
                "agents.ToolGuardrailFunctionOutput.reject_content", "agents.ToolGuardrailFunctionOutput.raise_exception") \
                and all(_literal(a) for a in v.args) and all(k.arg and _literal(k.value) for k in v.keywords)
        return False

    def input_of(self, arg, scope=None):
        """F2/F3: the helper's argument is the tool's parameter (tool) or exactly the framework's input (hook); in
        a Claude Agent SDK hook, inside a scope naming only tools that execute it, one field of the tool input."""
        if self.role == "tool":
            return isinstance(arg, ast.Name) and arg.id in self.params
        ch = _chain(arg)
        if not ch:
            return False
        if (ch[0], tuple(ch[1])) in self.input_paths:
            return True
        return self.role == "sdk-hook" and scope is not None and len(ch[1]) == 2 and \
            (ch[0], (ch[1][0],)) in self.input_paths and ch[1][1] in SDK_FIELD_TOOLS and scope <= SDK_FIELD_TOOLS[ch[1][1]]

    def names(self, e):
        """F4: the tool names a tool-name test selects, or None."""
        if not (isinstance(e, ast.Compare) and len(e.ops) == 1 and isinstance(e.ops[0], (ast.Eq, ast.In))):
            return None
        left, right = e.left, e.comparators[0]
        sides = [(left, right)] + ([(right, left)] if isinstance(e.ops[0], ast.Eq) else [])
        for name_side, val in sides:
            ch = _chain(name_side)
            vals = _lits(self.idx, self.mod, val)
            if ch and (ch[0], tuple(ch[1])) in self.name_paths and vals:
                return name_side, set(vals)
        return None

    def guard_stmt(self, st):
        """(input node, refusal ok) for `if refuses(X): <refusal>` with no else, else None."""
        if not (isinstance(st, ast.If) and not st.orelse):
            return None
        arg = self.helper_call(st.test)
        if arg is None:
            return None
        return arg, self.refusal(st.body)

    def credit(self, st, arg, tools):
        g = Guard("refusal", self.mod.where(st), self.label, secret=True, destructive=True, tools=tools)
        g.subject = arg.id if self.role == "tool" else None
        return (st.end_lineno or st.lineno, g)

    def noncanonical(self, node, why, tools=None):
        where = self.mod.where(node)
        return (node.end_lineno or node.lineno, Guard("refusal", where, self.label, tools=tools, partial={
            c: f"{where} {self.label}: {why} (see --canonical-forms)" for c in CLASSES}))

    def refusals(self):
        """[(last line, Guard)]: credited refusals earn the helper's classes; any other refusal says why it earns nothing."""
        out, credited, why_not, leading = [], [], "", True
        seen = set()
        for st in self.body():
            if not leading:
                break
            g = self.guard_stmt(st)
            scoped = self.names(st.test) if isinstance(st, ast.If) and not st.orelse and self.role != "tool" else None
            if g is not None:
                arg, ok = g
                if not ok or not self.input_of(arg):
                    why_not = why_not or (f"line {st.lineno}: the refusal is not the documented one for this hook"
                                          if not ok else f"line {st.lineno}: refuses() is not given "
                                          + ("a parameter of the tool" if self.role == "tool" else "the framework's tool input"))
                    leading = False
                    continue
                seen.add(st)
                self.allowed.update(n for n in ast.walk(arg) if isinstance(n, ast.Name))
                credited.append((st, arg, None))
            elif scoped is not None and st.body and self.guard_stmt(st.body[0]) is not None:
                inner = st.body[0]
                arg, ok = self.guard_stmt(inner)
                if not ok or not self.input_of(arg, scoped[1]):
                    why_not = why_not or f"line {inner.lineno}: the scoped refusal is not the documented one"
                    leading = False
                    continue
                self.allowed.update(n for n in ast.walk(arg) if isinstance(n, ast.Name))
                self.allowed.update(n for n in ast.walk(scoped[0]) if isinstance(n, ast.Name))
                seen.update((st, inner))
                credited.append((inner, arg, scoped[1]))
                if len(st.body) > 1:
                    leading = False        # anything after the scoped refusal may exit for that tool
            else:
                leading = False
        if self.role == "tool":
            for st, arg, _ in credited:
                why = self.tool_value_why(arg.id)
                if why:
                    why_not = why_not or why
        if self.blocked or (credited and not self.helper):
            why_not = self.blocked or self.helper_why
        if not why_not and credited:
            why_not = self.inert_why(own=True)
        for st, arg, tools in credited:
            out.append(self.noncanonical(st, why_not, tools) if why_not else self.credit(st, arg, tools))
        # every other refusal: a helper refusal out of place, or a hand-written one
        for n in ast.walk(self.fn):
            if n in seen or not isinstance(n, ast.If) or not self.looks_refusing(n):
                continue
            if self.helper_call(n.test) is not None:
                out.append(self.noncanonical(n, f"line {n.lineno}: the helper refusal is not among the function's "
                                                "first statements, or its shape is not F2/F3"))
            else:
                out.append(self.noncanonical(n, f"line {n.lineno}: {HAND_WRITTEN}"))
        return out

    def looks_refusing(self, node) -> bool:
        """A refusal of any shape: an `if` on the input whose body refuses the way this hook or tool can."""
        if not _uses(node.test, self.inputs | self.restricted | {KIT_GUARD_NAME}):
            return False
        for st in node.body:
            for n in ast.walk(st):
                if isinstance(n, (ast.Return, ast.Raise)) and self.role in ("tool", "maf-hook", "guardrail-hook"):
                    return True
                if isinstance(n, ast.Return) and n.value is not None and self.role in ("adk-hook", "crewai-hook",
                                                                                       "sdk-hook", "sdk-permission"):
                    return True
                if isinstance(n, ast.Attribute) and n.attr == "cancel_tool" and isinstance(n.ctx, ast.Store):
                    return True
                if isinstance(n, (ast.Continue, ast.Break)):
                    return True
        return False

    def tool_value_why(self, p):
        """F2: every use of P other than the helper's argument is the operation argument of a capability call."""
        r = _rebound(self.fn, p)
        if r is not None:
            return f"`{p}` is rebound or changed at line {getattr(r, 'lineno', '?')}"
        aliases = _local_aliases(self.mod, self.fn)
        for n in ast.walk(self.fn):
            if not (isinstance(n, ast.Name) and n.id == p) or n in self.allowed:
                continue
            call = self.parents.get(n)
            if isinstance(call, ast.keyword):
                call = self.parents.get(call)
            if isinstance(call, ast.Call) and isinstance(call.func, (ast.Name, ast.Attribute)):
                full = _full_name(self.mod, aliases, call.func)
                cap = _capability(call, full, full.split(".")[0], False)
                if cap == "computer":
                    cap = None
                if cap and _op_arg(call, cap, full) is n:
                    continue
            return (f"line {getattr(n, 'lineno', '?')}: `{p}` is used other than as the operation argument of a "
                    "capability call (aliased, passed on, wrapped or another argument)")
        return ""

    def inert_why(self, own=False):
        """F5: why this hook may change the input another hook checked, or ''."""
        if self.role in ("tool", "guardrail-hook"):
            return ""
        for n in ast.walk(self.fn):
            if not (isinstance(n, ast.Name) and n.id in self.restricted) or n in self.allowed:
                continue
            top = _chain_top(n, self.parents)
            p = self.parents.get(top)
            if isinstance(p, ast.Call) and p.args == [top] and not p.keywords and \
                    self.mod.full(p.func) in PURE_WRAPS and not self.shadowed(p.func):
                continue                                    # copy.deepcopy(x), json.dumps(x), str(x), repr(x)
            if isinstance(p, (ast.Compare, ast.FormattedValue)) or (isinstance(p, ast.UnaryOp) and isinstance(p.op, ast.Not)) \
                    or (isinstance(p, (ast.If, ast.While, ast.IfExp, ast.Assert)) and p.test is top):
                if isinstance(getattr(top, "ctx", ast.Load()), ast.Load):
                    continue                                # a read that is compared or tested
            if self.next and isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and p.func.id == self.next \
                    and top is n and p.args == [n] and not p.keywords:
                continue                                    # call_next(context)
            return (f"{self.mod.where(n)} `{n.id}` is used outside the guard (aliased, changed or passed on), so the "
                    "input the tool runs with may not be the one checked")
        if self.role in ("sdk-hook",):
            for r in (x for x in ast.walk(self.fn) if isinstance(x, ast.Return)):
                if not _sdk_safe_return(self.idx, self.mod, r.value):
                    return (f"{self.mod.where(r)} this hook may return `updatedInput` (or a value the audit cannot "
                            "read), which changes the input after the check")
        return ""

    def shadowed(self, func):
        """A name the pure wrappers rely on (`str`, `copy`, `json`) that is not the real one."""
        head = _dotted(func).split(".")[0]
        tampered = self.idx.tampered()
        return len(_binds(self.mod.tree, head)) != (1 if head in self.mod.alias else 0) or \
            (head if head in self.mod.alias else "builtins") in tampered or "*" in tampered


def _sdk_deny_literal(v) -> bool:
    """F3: exactly {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny'
    [, 'permissionDecisionReason': '<literal>']}}."""
    if not (isinstance(v, ast.Dict) and len(v.keys) == 1 and isinstance(v.keys[0], ast.Constant)
            and v.keys[0].value == "hookSpecificOutput" and isinstance(v.values[0], ast.Dict)):
        return False
    inner = v.values[0]
    if None in inner.keys or not all(isinstance(k, ast.Constant) for k in inner.keys):
        return False
    keys = [k.value for k in inner.keys]
    vals = dict(zip(keys, inner.values))
    return len(keys) == len(set(keys)) and set(keys) <= {"hookEventName", "permissionDecision", "permissionDecisionReason"} \
        and all(isinstance(x, ast.Constant) and isinstance(x.value, str) for x in inner.values) \
        and vals.get("permissionDecision") is not None and vals["permissionDecision"].value == "deny" \
        and vals.get("hookEventName") is not None and vals["hookEventName"].value == "PreToolUse"


def _sdk_safe_return(idx, mod, v, depth=0) -> bool:
    """F5: a hook return that cannot carry updatedInput: None, a dict literal with literal keys (none of them
    updatedInput, at any depth of dict literals), or a call of a module function whose every return is one."""
    if v is None or (isinstance(v, ast.Constant) and v.value is None):
        return True
    if isinstance(v, ast.Dict):
        if None in v.keys or not all(isinstance(k, ast.Constant) and isinstance(k.value, str) for k in v.keys):
            return False
        if any(k.value in ("updatedInput", "updated_input") for k in v.keys):
            return False
        return all(_sdk_safe_return(idx, mod, x, depth) if isinstance(x, ast.Dict) else
                   not any(isinstance(y, ast.Dict) for y in ast.walk(x)) for x in v.values)
    if isinstance(v, ast.Call) and depth < 2 and isinstance(v.func, ast.Name):
        k = idx.resolve(mod, v.func)
        if k[0] == "def" and not k[2].decorator_list and len(_binds(k[1].tree, k[2].name)) == 1 and \
                k[1].path not in idx.tampered():
            return all(_sdk_safe_return(idx, k[1], r.value, depth + 1) for r in ast.walk(k[2]) if isinstance(r, ast.Return))
    return False


def _canonical_refusals(idx, mod, fn, kinds, label, role):
    return _Canon(idx, mod, fn, kinds, label, role).refusals()


def _hook_inert(idx, mod, node, role):
    """F5 for a hook that is not the credited one: why it may change the input, or ''."""
    kind = idx.resolve(mod, node.func if isinstance(node, ast.Call) else node)
    if kind[0] != "def":
        return f"{mod.where(node)} {mod.src(node)[:40]} is a hook the audit cannot read, so it may change the input"
    c = _Canon(idx, kind[1], kind[2], (), "hook", role)
    return c.blocked or c.inert_why()


def _void(guards, why):
    """Credited refusals that another hook may undo become UNRESOLVED with the reason."""
    return [_unbound(g, why) if (g.secret or g.destructive or g.path) and g.kind == "refusal" else g for g in guards]


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
        elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)) and isinstance(n.target, ast.Name):
            local.setdefault(n.target.id, ast.Subscript(value=n.iter, slice=ast.Constant(value=0)))   # an element
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if isinstance(item.optional_vars, ast.Name):
                    local.setdefault(item.optional_vars.id, item.context_expr)
    out.update(local)
    for name in list(out):         # a callee alias bound more than once may be any of its values when it runs
        if isinstance(out[name], (ast.Name, ast.Attribute)) and \
                (len(_binds(fn, name)) > 1 or (name not in local and len(_binds(mod.tree, name)) > 1)):
            out[name] = ast.Name(id="<rebound>")
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
# Irreversible by operation, whatever the target: deletes, and destructive words in a fixed command.
DELETE_FUNCS = {"shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs"}
DELETE_ATTRS = {"unlink", "rmdir"}
FIXED_DESTRUCTIVE_RX = r"(^|[\s;&|(`])(rm|rmdir|shred|unlink)(\s|$)|\bgit\s+(push|reset\s+--hard|clean)\b|\bmkfs\b"
PATH_CTORS = {"pathlib.Path", "Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath"}
PATH_SAME = {"resolve", "absolute", "expanduser"}       # the same file, another spelling


def _path_ctor(mod, aliases, node, depth=0):
    """The Path(...) call a receiver is built from, or None: `Path('.env')`, a name bound to one, `REPO / 'x'`,
    `Path(p).resolve()`. Returned with the path text joined when the parts are literals."""
    if depth > 5:
        return None
    if isinstance(node, ast.Call) and _full_name(mod, aliases, node.func) in PATH_CTORS:
        return node
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in PATH_SAME:
        return _path_ctor(mod, aliases, node.func.value, depth + 1)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        base = _path_ctor(mod, aliases, node.left, depth + 1)
        if base is None:
            return None
        head = base.args[0] if base.args and isinstance(base.args[0], ast.Constant) else \
            ast.Constant(value="." if not base.args else "<base>")   # a base chosen at start-up, a literal tail
        return ast.Call(func=base.func, args=[ast.BinOp(left=head,
                                                         op=ast.Add(), right=ast.BinOp(left=ast.Constant(value="/"),
                                                                                       op=ast.Add(), right=node.right))],
                        keywords=[], lineno=getattr(node, "lineno", 0))
    if isinstance(node, ast.Name) and node.id in aliases:
        return _path_ctor(mod, aliases, aliases[node.id], depth + 1)
    return None


def _data_like(mod, aliases, node, tainted, depth=0) -> bool:
    """True when a method's receiver is plain data (a literal, the tool's input, a parsed or returned value of a safe
    or capability call, an element or field of such data), so its methods do nothing outside the process."""
    if depth > 6 or node is None:
        return False
    rec = lambda n: _data_like(mod, aliases, n, tainted, depth + 1)
    if isinstance(node, (ast.Constant, ast.JoinedStr, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(rec(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(rec(v) for v in node.values)
    if isinstance(node, ast.BinOp):
        return rec(node.left) and rec(node.right)
    if isinstance(node, (ast.Subscript, ast.Attribute)):
        return rec(node.value)
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return rec(aliases[node.id])
        return node.id in tainted
    if isinstance(node, ast.Call):
        full = _full_name(mod, aliases, node.func)
        if full in _BUILTIN_SAFE or full in SAFE_CALLS or full.split(".")[0] in SAFE_HEADS or full in SHELL_FUNCS:
            return True
        if isinstance(node.func, ast.Attribute):
            return rec(node.func.value)        # a method's result on data is data (`text.splitlines()`)
    return False


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


def _unbound(g, why):
    """A refusal that does not control this call: what it covered becomes UNRESOLVED with the reason."""
    if not (g.secret or g.destructive or g.path):
        return g
    out = Guard("refusal", g.where, g.label, tools=g.tools, partial={c: why for c in CLASSES if getattr(g, c)})
    out.partial.update({c: w for c, w in g.partial.items() if c not in out.partial})
    return out


def function_reach(idx: Index, mod: Module, fn, tainted=None, depth=0, carry=()) -> Reach:
    """Follow the data a tool receives into calls that run commands, write or read files, fetch or use a computer.
    A capability is never dropped silently: a call the audit cannot follow is UNRESOLVED, and a call with a fixed
    target is still classified (a fixed `git push` is irreversible; a fixed `git status` is listed, not hidden)."""
    reach = Reach()
    if tainted is None:
        tainted = {a.arg for a in fn.args.args + fn.args.kwonlyargs + ([fn.args.vararg] if fn.args.vararg else [])
                   + ([fn.args.kwarg] if fn.args.kwarg else [])} - TAINT_SKIP
    tainted = _taint(fn, tainted)
    aliases = _local_aliases(mod, fn)
    refusals = [(0, g) for g in carry] + _canonical_refusals(idx, mod, fn, ("early",), "inline refusal (early return)", "tool")

    def before(line):
        return [g for end, g in refusals if end < line]   # a capability inside the refusing branch is not guarded by it

    def bind(gs, cat, call):
        """F2: a helper refusal guards a call only when the call's operation argument is the tested parameter; it
        says nothing about other calls."""
        out = []
        for g in gs:
            if g.subject is None:
                out.append(g)
                continue
            full = _full_name(mod, aliases, call.func) if isinstance(call.func, (ast.Name, ast.Attribute)) else ""
            arg = _op_arg(call, cat, full)
            tampered = idx.tampered()
            head = _dotted(call.func).split(".")[0]
            rebound = head in aliases and (len(_binds(fn, head)) > 1 or len(_binds(mod.tree, head)) > 1)
            if isinstance(arg, ast.Name) and arg.id == g.subject and not rebound and \
                    full.split(".")[0] not in tampered and "*" not in tampered and "builtins" not in tampered:
                out.append(g)
        return out

    def add(cat, node, target=None):
        if not any(c == cat and w == mod.where(node) for c, w, _ in reach.caps):
            reach.caps.append((cat, mod.where(node), bind(before(node.lineno), cat, node)))

    for call in (n for st in fn.body for n in ast.walk(st) if isinstance(n, ast.Call)):   # decorators are not the body
        args = list(call.args) + [k.value for k in call.keywords]
        hit = any(_uses(a, tainted) for a in args)
        if not isinstance(call.func, (ast.Name, ast.Attribute)):
            reach.unresolved.append(f"{mod.where(call)} {mod.src(call.func)[:40]}(...) is a computed call the audit cannot follow")
            continue
        full = _full_name(mod, aliases, call.func)
        head = full.split(".")[0]
        on_tainted = isinstance(call.func, ast.Attribute) and _uses(call.func.value, tainted)
        attr = call.func.attr if isinstance(call.func, ast.Attribute) else ""
        if attr and isinstance(call.func.value, ast.Call) and attr not in WRITE_ATTRS | READ_ATTRS | {"open"}:
            if hit and not _data_like(mod, aliases, call.func.value, tainted):
                inner = call.func.value       # requests.Session().get(url): the input goes to the client built inline
                ifull = _full_name(mod, aliases, inner.func)
                icap = _capability(inner, ifull, ifull.split(".")[0], False)
                if icap:
                    add(icap if icap != "open" else "read", call)
                else:
                    reach.unresolved.append(f"{mod.where(call)} {mod.src(call.func)[:40]}(...) gives the tool's input to an "
                                            "object the audit cannot follow")
            continue     # e.g. urlopen(url).read(): the inner call is the capability
        cap = _capability(call, full, head, on_tainted)
        target = call
        if cap is None and not on_tainted and attr in WRITE_ATTRS | READ_ATTRS | {"open"}:
            pc = _path_ctor(mod, aliases, call.func.value)      # Path('.env').read_text(): a read, by operation
            if pc is not None:
                target, hit = pc, hit or any(_uses(a, tainted) for a in pc.args)
                cap = "read" if attr in READ_ATTRS else "open" if attr == "open" else "write"
        if cap == "computer":
            add("computer", call); continue
        if cap is not None and not hit and not on_tainted:
            text = _fixed_text(idx, mod, target, "open" if cap == "read" or target is not call else cap)
            if full in DELETE_FUNCS or (target is not call and attr in DELETE_ATTRS):
                add("irreversible", call)          # a delete is irreversible whatever its target
            elif text is None:
                reach.unresolved.append(f"{mod.where(call)} {full}(...) acts on a target the audit cannot read")
            elif cap in ("shell", "write") and (re.search(DESTRUCTIVE_RX, text) or re.search(FIXED_DESTRUCTIVE_RX, text)):
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
            add(cap, call, target if target is not call else None)
        elif isinstance(call.func, ast.Attribute) and not on_tainted and head not in mod.alias:
            bound = aliases.get(head)
            if _data_like(mod, aliases, call.func.value, tainted):
                continue     # a method on data: "".join(...), a parsed dict, a compiled regex, a process's output
            origin = "" if bound is None or _is_data(bound) else _full_name(mod, aliases, bound.func if isinstance(bound, ast.Call) else bound)
            if isinstance(bound, ast.Call):
                ocap = _capability(bound, origin, origin.split(".")[0], False)
                if ocap is None and isinstance(bound.func, ast.Attribute) and bound.func.attr == "open" and \
                        _path_ctor(mod, aliases, bound.func.value) is not None:
                    ocap = "open"
                if ocap == "open":
                    continue     # a handle opened above: the open() call is the capability
                if ocap:
                    add(ocap, call); continue
            reach.unresolved.append(f"{mod.where(call)} {mod.src(call.func)[:40]}(...) is a method on an object the audit cannot follow")
        elif full in SAFE_CALLS or head in SAFE_HEADS or full in _BUILTIN_SAFE or on_tainted:
            continue
        elif _is_kit_guard(idx, mod, call.func):
            continue         # the kit's pinned guard helper only reads its argument
        else:            # followed whether or not it receives the tool's input: a fixed helper can still push
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
                handed = []           # what a callee inherits: unproven refusals stay unproven inside it
                for g in before(call.lineno):
                    if g.subject is None:     # a credited refusal never reaches into a helper (F2: P is not passed on)
                        handed.append(g)
                sub = function_reach(idx, callee_mod, callee, passed if hit else set(), depth + 1, carry=handed)
                reach.merge(sub)
            elif kind[0] == "external" and kind[1].split(".")[0] in SAFE_HEADS:
                continue
            else:
                reach.unresolved.append(f"{mod.where(call)} {full}(...) is a call the audit cannot follow")
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
                        guards += _callable_guards(idx, mod, el, "tool input guardrail", ("early", "dict", "false", "deny"),
                                                   role="guardrail-hook")
    return guards, name


def _callable_canon(idx, mod, node, label, kinds, role="hook"):
    """([Guard], why it may change the input or '') for a guard given as a function or object. Conditions that apply
    to every tool are combined into one guard; conditions limited to named tools stay separate guards."""
    kind = idx.resolve(mod, node.func if isinstance(node, ast.Call) else node)
    if kind[0] != "def":
        why = f"{mod.where(node)} {mod.src(node)[:50]} is not followed by the audit"
        return [Guard("refusal", mod.where(node), label, unresolved=why)], why
    gm, fn = kind[1], kind[2]
    c = _Canon(idx, gm, fn, kinds, label, role)
    found = [g for _, g in c.refusals()]
    inert = c.blocked or c.inert_why()
    if not found:
        return [Guard("refusal", gm.where(fn), label, unresolved=f"{gm.where(fn)} {fn.name} never refuses a call that the audit can see")], inert
    return _combine(found, label), inert


def _callable_guards(idx, mod, node, label, kinds, role="hook") -> list:
    return _callable_canon(idx, mod, node, label, kinds, role)[0]


def _hook_set(results):
    """F5: the guards of several hooks on one agent and event. When any of them may change the input, every credited
    refusal among them becomes UNRESOLVED with that reason."""
    guards = [g for gs, _ in results for g in gs]
    why = next((w for _, w in results if w), "")
    return _void(guards, why) if why else guards


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
        if _decorated(idx, fmod, fn):
            reach.unresolved.append(_decorated(idx, fmod, fn))
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
        hooks, strands = _kw(call, "hooks"), []
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
                            if m and isinstance(c.args[1], ast.Attribute) and _dotted(c.args[1]) == f"self.{mname}":
                                canon = _Canon(idx, cm, m, ("cancel",), "BeforeToolCallEvent cancel_tool", "strands-hook")
                                got = [g for _, g in canon.refusals()]
                                found = True
                                strands.append(((_combine(got, "BeforeToolCallEvent cancel_tool") if got else
                                                 [Guard("refusal", cm.where(m), "hook", unresolved=f"{cm.where(m)} hook never cancels a call the audit can see")]),
                                                canon.blocked or canon.inert_why()))
                            else:
                                found = True
                                why = f"{cm.where(c)} BeforeToolCallEvent callback {cm.src(c.args[1])[:40]} is not a method the audit can read"
                                strands.append(([Guard("refusal", cm.where(c), "hook", unresolved=why)], why))
                    if not found:
                        guards.append(Guard("refusal", hmod.where(el), "hook provider", unresolved=f"{hmod.where(el)} hook provider registers no BeforeToolCallEvent callback the audit can read"))
                else:
                    why = f"{hmod.where(el)} hook {hmod.src(el)[:40]} is not followed"
                    strands.append(([Guard("refusal", hmod.where(el), "hook", unresolved=why)], why))
            undo = idx.cancel_undo()
            if undo:
                strands.append(([], undo))
            guards += _hook_set(strands)
    elif track == "google-adk":
        cb = _kw(call, "before_tool_callback")
        if cb is not None:
            guards += _hook_set([_callable_canon(idx, mod, cb, "before_tool_callback", ("dict",), role="adk-hook")])
    elif track == "microsoft-agent-framework":
        mw = _kw(call, "middleware")
        if mw is not None:
            mmod, lst = _tool_list(idx, mod, mw)
            results = []
            for el in (lst.elts if isinstance(lst, (ast.List, ast.Tuple)) else [lst]):
                gs, why = _callable_canon(idx, mmod, el, "function middleware", ("early",), role="maf-hook")
                # an observing middleware (e.g. a trace) is not a guard, but it must leave the input as it is (F5)
                results.append(([g for g in gs if not (g.unresolved and "never refuses" in g.unresolved)], why))
            guards += _hook_set(results)
    elif track == "crewai":
        results = []
        for n in mod.tree.body:   # hooks registered in this module apply to its agents
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and _dotted(n.value.func).endswith("register_before_tool_call_hook") and n.value.args:
                gs, why = _callable_canon(idx, mod, n.value.args[0], "before-tool-call hook", ("false",), role="crewai-hook")
                results.append(([g for g in gs if not (g.unresolved and "never refuses" in g.unresolved)], why))
        other = idx.crewai_hooks(mod)    # CrewAI hooks are global: one registered anywhere else runs too (F5)
        if other:
            results.append(([], other))
        guards += _hook_set(results)
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
        return [("tools", _unresolved_reach(f"{mod.where(call)} tools={mod.src(tools_kw)[:40]} is not a list the audit can read"), [])], ""
    allowed = strs(allowed_kw) if allowed_kw is not None else []
    if allowed is None:      # unknown auto-approvals: nothing can be assumed to need a person
        allowed = list(available)
    mode = _kw(call, "permission_mode")
    mode = mode.value if isinstance(mode, ast.Constant) else "default"
    deny_rules = strs(_kw(call, "disallowed_tools")) if _kw(call, "disallowed_tools") is not None else []
    if deny_rules is None:   # an unreadable deny list removes nothing and refuses nothing
        deny_rules = []
    hooks_kw = _kw(call, "hooks")
    hook_results, hook_guards = [], []
    if isinstance(hooks_kw, ast.Dict):
        for k, v in zip(hooks_kw.keys, hooks_kw.values):
            if not (isinstance(k, ast.Constant) and k.value == "PreToolUse"):
                continue
            if not isinstance(v, (ast.List, ast.Tuple)):
                hook_results.append((".*", [], f"{mod.where(v)} PreToolUse hooks {mod.src(v)[:40]} are not a list the audit can read"))
                continue
            for hm in v.elts:
                hl = _kw(hm, "hooks") if isinstance(hm, ast.Call) else None
                if not isinstance(hl, (ast.List, ast.Tuple)):
                    hook_results.append((".*", [], f"{mod.where(hm)} a PreToolUse matcher's hooks are not a list the audit can read"))
                    continue
                matcher = _kw(hm, "matcher")
                pattern = ".*" if matcher is None or (isinstance(matcher, ast.Constant) and matcher.value is None) \
                    else _const_str(idx, mod, matcher)
                for h in hl.elts:
                    gs, why = _callable_canon(idx, mod, h, "PreToolUse deny hook", ("deny",), role="sdk-hook")
                    gs = [g for g in gs if not (g.unresolved and "never refuses" in g.unresolved)]
                    if pattern is None:
                        gs = [Guard("refusal", g.where, g.label, unresolved=f"{mod.where(matcher)} hook matcher {mod.src(matcher)[:40]} is not readable") for g in gs]
                    hook_results.append((pattern or ".*", gs, why))
    elif hooks_kw is not None:
        hook_results.append((".*", [], f"{mod.where(hooks_kw)} hooks={mod.src(hooks_kw)[:40]} is not a dict the audit can read"))
    # can_use_tool decides, instead of a person, for every tool that is not auto-approved
    cut = _kw(call, "can_use_tool")
    cut_guards, cut_why = [], ""
    if cut is not None:
        cut_guards, _ = _callable_canon(idx, mod, cut, "can_use_tool deny", ("deny",), role="sdk-permission")
        cut_guards = [g for g in cut_guards if not (g.unresolved and "never refuses" in g.unresolved)] or [Guard(
            "refusal", mod.where(cut), "can_use_tool", unresolved=f"{mod.where(cut)} can_use_tool decides instead of a "
            "person, and the audit cannot see it refuse")]
        cut_why = _can_use_tool_changes(idx, mod, cut)
        if cut_why:          # a callback that may rewrite the input cannot vouch for the input it allows either
            cut_guards = _void(cut_guards, cut_why)
    why = next((w for _, _, w in hook_results if w), "") or cut_why
    for pattern, gs, _ in hook_results:
        for g in (_void(gs, why) if why else gs):
            hook_guards.append((pattern, g))
    servers, server_problem = _sdk_servers(idx, mod, call)
    # configuration the audit cannot read is never "no tools": an unreadable map, an unreadable server, or a
    # server-wide approval of a server whose tools it cannot list make the whole agent UNRESOLVED
    problems = [server_problem] if server_problem else []
    problems += [v for v in servers.values() if isinstance(v, str)]
    for a in allowed:
        parts = a.split("(")[0].split("__")
        if a.startswith("mcp__") and len(parts) >= 2 and (len(parts) == 2 or parts[2] == "*") and \
                not isinstance(servers.get(parts[1]), dict):
            problems.append(f"{mod.where(call)} allowed_tools {a} approves every tool of MCP server {parts[1]!r}, "
                            "whose tools the audit cannot list (it is not an in-process server in mcp_servers here)")
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
        if not auto and cut is not None:
            guards += cut_guards
        elif not auto:
            guards.append(Guard("approval", mod.where(call), f"{base} not in allowed_tools (a person approves)"))
        for d in deny_rules:       # the same scope standard as Claude Code settings: a scoped rule covers its scope
            if d.split("(")[0] == base and "(" in d:
                guards.append(_rule_guard(d, "disallowed_tools", mod.where(call)))
        for pattern, g in hook_guards:      # the matcher picks the tools; a name test inside the hook narrows further
            if _matches(pattern, base) and (g.tools is None or base in g.tools):
                guards.append(g)
        tools.append((base, reach, guards))
    return tools, "; ".join(dict.fromkeys(problems))


def _can_use_tool_changes(idx, mod, node) -> str:
    """F5: why can_use_tool may change the input after the PreToolUse hooks checked it, or ''."""
    kind = idx.resolve(mod, node.func if isinstance(node, ast.Call) else node)
    if kind[0] != "def":
        return f"{mod.where(node)} can_use_tool {mod.src(node)[:40]} is not readable, so it may change the input"
    cm, fn = kind[1], kind[2]
    for n in ast.walk(fn):
        if isinstance(n, ast.Return) and not (isinstance(n.value, ast.Call) and cm.full(n.value.func) in (
                "claude_agent_sdk.PermissionResultAllow", "claude_agent_sdk.PermissionResultDeny")
                and not n.value.args and all(k.arg and k.arg != "updated_input" for k in n.value.keywords)):
            return f"{cm.where(n)} can_use_tool may return updated_input (or a value the audit cannot read)"
    return ""


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
                sdk_tools, sdk_problem = _sdk_agent(idx, mod, call)
                agents.append((label, mod.where(call), sdk_tools, [], sdk_problem))
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
        out[cid] = (st, ev, f"{name}: {fixes[i]}" + (" Where the audit cannot prove a guard, write it in a canonical form "
                                                     "(audit.py --canonical-forms; kit/shared/kit_guard.py is the kit's helper) "
                                                     "and keep tools as plain functions in this repo." if st == "UNRESOLVED" else ""))
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
    lines, problem, escapes = {}, "", []
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
        if sb.get("enabled"):
            # Claude Code defaults: autoAllowBashIfSandboxed and allowUnsandboxedCommands are on unless set to false
            sandbox_on = True
            sandbox_auto = sandbox_auto or sb.get("autoAllowBashIfSandboxed", True) is not False
            if sb.get("excludedCommands"):
                escapes.append(f"{r.rel(p)} sandbox.excludedCommands {sb['excludedCommands']!r} run outside the sandbox")
            if sb.get("allowUnsandboxedCommands", True) is not False:
                escapes.append(f"{r.rel(p)} sandbox.allowUnsandboxedCommands is not false, so a command may leave the sandbox")
            fs = sb.get("filesystem", {})
            if not isinstance(fs, dict) or fs.get("disabled", False) is not False:
                escapes.append(f"{r.rel(p)} sandbox.filesystem.disabled is set (or sandbox.filesystem is not readable), so "
                               "the sandbox applies no filesystem rules to commands")
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
        skipped = tool == "Bash" and sandbox_auto    # sandbox auto-allow runs sandboxed commands without the ask
        if whole_ask and skipped:
            guards.append(Guard("approval", at(whole_ask[0]), f"ask {whole_ask[0]}", unresolved=(
                f"{at(whole_ask[0])} ask {whole_ask[0]} is skipped for sandboxed commands while sandbox auto-allow "
                "(autoAllowBashIfSandboxed, on by default) is on")))
        elif whole_ask:   # ask outranks allow: a person approves every call
            guards.append(Guard("approval", at(whole_ask[0]), f"ask {whole_ask[0]}"))
        elif not auto:
            guards.append(Guard("approval", first, f"{tool} needs approval (not in allow, default mode)"))
        for kind in ("ask", "deny"):   # a scoped rule covers only its scope
            for x in rules(kind, tool):
                if whole(x):
                    continue
                g = _rule_guard(x, kind, at(x))
                if kind == "ask" and skipped and (g.secret or g.destructive):
                    g = Guard("refusal", at(x), f"ask {x}", unresolved=f"{at(x)} ask {x} may be skipped by sandbox auto-allow")
                guards.append(g)
        if cat == "read":     # Read deny rules also bind Grep and Glob
            guards += [_rule_guard(x, "deny", at(x)) for x in rules("deny", "Read") if tool != "Read" and not whole(x)]
        elif tool == "Bash" and sandbox_on:
            # the sandbox applies Read deny rules to every command's file reads, unless a command can leave it
            reads = [_rule_guard(x, "deny", at(x)) for x in rules("deny", "Read") if not whole(x)]
            if escapes:
                guards += [Guard("refusal", g.where, g.label, unresolved=f"{g.label} binds Bash only inside the sandbox, "
                                 f"and {escapes[0]}") for g in reads if g.secret]
            else:
                guards += reads
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
    ap.add_argument("--canonical-forms", action="store_true", help="print the guard forms the audit credits, then exit")
    a = ap.parse_args(argv)
    if a.canonical_forms:
        print(canonical_forms_text())
        return 0
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
