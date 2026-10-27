"""kit_guard: the harness kit's guard helper (version 2, harness-marketplace 1.4.5). Standard library only.

    import subprocess
    from kit_guard import refuses

    def run(command: str) -> str:
        if refuses(command):
            return "refused: secret path or destructive command"
        return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

refuses(value) is True when value names a secret path or is a destructive command. value may be a string (a command,
a path or a URL) or a tool's whole input (a dict or a list): every string inside it is checked on its own, keys
included, and a list of strings is also checked as one argument vector (`['rm', '-rf', 'x']`).

The classes, as this helper defines them (harness-audit credits exactly these):
  secret       a path part (or a glob that can match one) named .env or starting with .env (.env.local, .env_prod,
               .envrc); ending in .pem, .key, .p12 or .pfx, also with a suffix (server.key.bak); id_rsa, id_dsa,
               id_ecdsa or id_ed25519, also with a suffix (.pub, .bak); .netrc; .pgpass; credentials or credentials.*;
               or inside .ssh, .aws, .gnupg, .azure, .kube, .docker or .config/gcloud. Read after shell quotes and
               backslashes are removed (or read as Windows separators), %-escapes decoded and simple braces expanded.
  destructive  in a shell command, after quotes are removed, wherever the program appears (after sudo, env, xargs,
               bash -c "...", inside $(...) or backticks): git push and git clean, whatever git options come first
               (-C dir, -c k=v, --git-dir=...); git reset with --hard, options in any order, abbreviations such as
               --ha included (and `reset --hard` after any program); git -c alias.*=... (an alias can run anything);
               rm with a recursive option in any position (-r, -R, -rf, -fr, -r -f, --recursive and its
               abbreviations, rm x -rf).
Not decoded (bound your claim accordingly): shell variables and parameter expansion ($X, ${X}), command output used
as a word, ANSI-C quoting ($'\\x2e'), encodings (base64), git aliases defined in config files, programs that delete
without these words (find -delete, a script file). A glob with no literal character (`*`) is not treated as a secret.

harness-audit credits `if refuses(<the tool's own parameter>): return <literal>` as the first statement of a tool
(and the framework contracts in `audit.py --canonical-forms`) only while this file is byte for byte the shipped one:
its sha256 is pinned in the audit. Copy it unchanged, and import it exactly as `from kit_guard import refuses`.
"""
from __future__ import annotations

import fnmatch
import re
import shlex
import urllib.parse

_SECRET_NAME = re.compile(r"^(\.env.*|.*\.(pem|key|p12|pfx)([._~-].*)?|id_(rsa|dsa|ecdsa|ed25519)([._~-].*)?|"
                          r"\.netrc|\.pgpass|credentials(\..*)?)$", re.I)
_SECRET_DIRS = {".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker"}
# names a glob is matched against: one of each kind above
_SECRET_SAMPLES = (".env", ".env.local", ".env_prod", ".envrc", "x.pem", "x.key", "x.p12", "x.pfx", "x.key.bak",
                   "id_rsa", "id_ed25519", ".netrc", ".pgpass", "credentials", "credentials.json", ".ssh", ".aws",
                   ".gnupg", ".azure", ".kube", ".docker", "gcloud")
_SEPARATORS = {";", "&", "&&", "|", "||", "|&", "(", ")", "\n", ";;", "&|"}
_GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix",
                        "--config-env", "--list-cmds"}


def _expand_braces(word, depth=0):
    """a{b,c}d -> [abd, acd] (simple, non-nested braces; at most 64 results)."""
    m = re.search(r"\{([^{}]*,[^{}]*)\}", word)
    if not m or depth > 4:
        return [word]
    out = []
    for part in m.group(1).split(","):
        out += _expand_braces(word[:m.start()] + part + word[m.end():], depth + 1)
        if len(out) > 64:
            break
    return out[:64]


def _unquoted(s):
    return re.sub(r"[\"'\\`]", "", s)


def _secret_part(part):
    if not part:
        return False
    low = part.lower()
    if _SECRET_NAME.match(low) or low in _SECRET_DIRS:
        return True
    if any(c in part for c in "*?["):
        if not re.sub(r"[*?\[\]!^]", "", part):
            return False                                  # `*`: no literal character, not treated as a secret
        for name in _SECRET_SAMPLES:
            if name.startswith(".") and not part.startswith("."):
                continue                                  # the shell's * and ? never match a leading dot
            if fnmatch.fnmatchcase(name, low):
                return True
    return False


def _secret_word(word):
    forms = {_unquoted(word), re.sub(r"[\"'`]", "", word).replace("\\", "/")}
    forms |= {urllib.parse.unquote(f) for f in forms}
    for w in (x for f in forms for x in _expand_braces(f)):
        parts = [p.lower() for p in re.split(r"[/\\=:,;@\s|&<>()]+", w)]
        if any(_secret_part(p) for p in parts):
            return True
        if any(a == ".config" and b == "gcloud" for a, b in zip(parts, parts[1:])):
            return True
    return False


def _tokens(s):
    """Shell words and separators; None when the text does not parse as shell words."""
    try:
        lex = shlex.shlex(s.replace("\n", " ; "), posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return None


def _segments(tokens):
    seg = []
    for t in tokens:
        if t in _SEPARATORS or set(t) <= set(";&|()<>"):
            if seg:
                yield seg
            seg = []
        else:
            seg.append(t)
    if seg:
        yield seg


def _program(word):
    return _unquoted(word).lstrip("$(").split("/")[-1].lower()


def _destructive_argv(words):
    """True when an argument vector runs a destructive command anywhere in it (after a wrapper such as sudo)."""
    words = [_unquoted(w).strip("`") for w in words]
    for i, w in enumerate(words):
        prog = _program(w)
        rest = words[i + 1:]
        if prog == "rm":
            for a in rest:
                if re.fullmatch(r"-[a-zA-Z]*[rR][a-zA-Z]*", a) or (len(a) >= 3 and "--recursive".startswith(a)) or \
                        a.startswith("--recursive="):
                    return True
        elif prog == "git":
            j = 0
            while j < len(rest):
                a = rest[j]
                if a in _GIT_OPTS_WITH_VALUE:
                    if a == "-c" and j + 1 < len(rest) and rest[j + 1].lower().startswith("alias."):
                        return True
                    j += 2
                    continue
                if a.startswith("-"):
                    if a.lower().startswith(("-calias.", "--config-env=alias.")):
                        return True
                    j += 1
                    continue
                sub = a.lower()
                if sub in ("push", "clean"):
                    return True
                if sub == "reset" and any(len(x) >= 3 and "--hard".startswith(x) for x in rest[j + 1:]):
                    return True
                break
        elif prog == "reset" and any(len(x) >= 3 and "--hard".startswith(x) for x in rest):
            return True                                   # a wrapper or alias of git (`g reset --hard`)
    return False


def _destructive_text(s, depth=0):
    if depth > 4:
        return False
    toks = _tokens(s)
    if toks is None:                                      # unbalanced quotes: judge the words without them
        toks = _tokens(_unquoted(s)) or _unquoted(s).split()
    toks = [t for tok in toks for t in re.split(r"(\$\(|`)", tok) if t not in ("", "$(", "`")]
    for seg in _segments(toks):
        if _destructive_argv(seg):
            return True
        for w in seg:                                      # bash -c "...", sh -c '...', eval "..."
            if any(c in w for c in " ;&|\n`$(") and _destructive_text(w, depth + 1):
                return True
    return False


def _strings(value, depth=0):
    """Every string inside value (dict keys and values, list items), each on its own; a list of strings is also
    yielded as one argument vector (a tuple)."""
    if isinstance(value, str):
        yield value
    elif depth > 20:
        yield str(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k, depth + 1)
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        if items and all(isinstance(v, str) for v in items) and not isinstance(value, (set, frozenset)):
            yield tuple(items)
        for v in items:
            yield from _strings(v, depth + 1)
    elif isinstance(value, bytes):
        yield value.decode("utf-8", "replace")
    elif value is not None:
        yield str(value)


def secret(value) -> bool:
    """True when value names a secret path (the secret class above)."""
    for s in _strings(value):
        words = list(s) if isinstance(s, tuple) else (_tokens(s) or []) + [s]
        if any(_secret_word(w) for w in words):
            return True
    return False


def destructive(value) -> bool:
    """True when value is a destructive command (the destructive class above)."""
    for s in _strings(value):
        if _destructive_argv(list(s)) if isinstance(s, tuple) else _destructive_text(s):
            return True
    return False


def refuses(value) -> bool:
    """True when value names a secret path or is a destructive command."""
    try:
        return secret(value) or destructive(value)
    except RecursionError:
        return True
