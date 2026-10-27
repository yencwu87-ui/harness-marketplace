"""kit_guard: the harness kit's guard helper (version 3, harness-marketplace 1.4.6). It imports nothing.

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
  secret       a path part named .env or starting with .env (.env.local, .env_prod, .envrc); ending in .pem, .key,
               .p12 or .pfx, or holding one of those followed by `.`, `_`, `~` or `-` and anything (server.key.bak);
               id_rsa, id_dsa, id_ecdsa or id_ed25519, alone or followed by `.`, `_`, `~` or `-` and anything (.pub,
               .bak); .netrc; .pgpass; credentials or credentials.<anything>; or inside .ssh, .aws, .gnupg, .azure,
               .kube, .docker or .config/gcloud. Upper and lower case are the same. Read after shell quotes and
               backslashes are removed (or read as Windows separators), %-escapes decoded and simple braces expanded.
  globs        a path part holding `*`, `?` or `[` is read as a superset of what the shell could expand it to: a
               bracket expression (POSIX classes included) is any one character, `?` is one character and `*` is any
               run of characters, a leading dot included. The part is secret when that superset can match a secret
               name above. The families are open (`<anything>.key-<anything>`, `.env<anything>`), so every part
               holding a `*` can match one and is refused (`*.py`, `src/*.json`, `tests/*`); `?` and brackets are
               refused only where a secret name fits (`id_?sa` is, `README.m?` is not). A glob part longer than 256
               characters is refused.
  destructive  in a shell command, after quotes are removed, wherever the program appears (after sudo, env, xargs,
               bash -c "...", inside $(...) or backticks): git push and git clean, whatever git options come first
               (-C dir, -c k=v, --git-dir=...); git reset with --hard, options in any order, abbreviations such as
               --ha included (and `reset --hard` after any program); git -c alias.*=... (an alias can run anything);
               rm with a recursive option in any position (-r, -R, -rf, -fr, -r -f, --recursive and its
               abbreviations, rm x -rf).
Not decoded (bound your claim accordingly): shell variables and parameter expansion ($X, ${X}), command output used
as a word, ANSI-C quoting ($'\\x2e'), encodings (base64), git aliases defined in config files, programs that delete
without these words (find -delete, a script file).

It uses only built-in functions and types, with its own small tokenizer, so no file in a repository can replace a
module it depends on. harness-audit credits `if refuses(<the tool's own parameter>): return <literal>` as the first
statement of a tool (and the framework contracts in `audit.py --canonical-forms`) only while this file is byte for byte
the shipped one: its sha256 is pinned in the audit. Copy it unchanged, and import it exactly as
`from kit_guard import refuses`.
"""

_SECRET_DIRS = (".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker")
_KEY_EXTS = ("pem", "key", "p12", "pfx")
_KEY_NAMES = ("rsa", "dsa", "ecdsa", "ed25519")
_SUFFIX_SEPS = (".", "_", "~", "-")
_SEPARATORS = {";", "&", "&&", "|", "||", "|&", "(", ")", "\n", ";;", "&|"}
_PUNCT = ";&|()<>"
_SPACE = " \t\r\n"
_PART_BREAKS = "/\\=:,;@|&<>()"
_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_HEX = "0123456789abcdefABCDEF"
_GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix",
                        "--config-env", "--list-cmds"}
_MAX_GLOB = 256


def _pattern(text):
    """A secret-name pattern as tokens: a character, '?' (any one) or '*' (any run)."""
    return tuple(("*",) if c == "*" else ("c", c) for c in text)


# The secret names above as patterns over one lower-case path part ('*' is any run of characters).
_SECRET_PATTERNS = tuple(_pattern(p) for p in (
    [".env*", ".netrc", ".pgpass", "credentials", "credentials.*"] + list(_SECRET_DIRS) +
    ["*." + e for e in _KEY_EXTS] + ["*." + e + s + "*" for e in _KEY_EXTS for s in _SUFFIX_SEPS] +
    ["id_" + k for k in _KEY_NAMES] + ["id_" + k + s + "*" for k in _KEY_NAMES for s in _SUFFIX_SEPS]))


def _bracket_end(s, i):
    """The index after the bracket expression opening at s[i] ('['), or -1 when it is not closed."""
    n, j = len(s), i + 1
    if j < n and s[j] in "!^":
        j += 1
    if j < n and s[j] == "]":
        j += 1                                          # a `]` first in the bracket is a member
    while j < n and s[j] != "]":
        if s[j] == "[" and j + 1 < n and s[j + 1] in ":.=":
            k = s.find(s[j + 1] + "]", j + 2)            # [:alpha:], [.x.], [=x=]
            j = k + 2 if k >= 0 else j + 1
        else:
            j += 1
    return j + 1 if j < n else -1


def _brackets_as_any(w):
    """w with each closed bracket expression replaced by `?`, so a `:` or `/` inside one does not split the part."""
    out, i = [], 0
    while i < len(w):
        j = _bracket_end(w, i) if w[i] == "[" else -1
        if j > 0:
            out.append("?")
            i = j
        else:
            out.append(w[i])
            i += 1
    return "".join(out)


def _glob(part):
    """A path part as pattern tokens, over-approximating the shell: a closed bracket expression is ('?',), `?` is
    ('?',), `*` is ('*',); an unclosed `[` is itself. None when the part holds no glob."""
    if not any(c in part for c in "*?["):
        return None
    out, i, n = [], 0, len(part)
    while i < n:
        c = part[i]
        if c == "*":
            if not out or out[-1] != ("*",):
                out.append(("*",))
            i += 1
        elif c == "?":
            out.append(("?",))
            i += 1
        elif c == "[":
            j = _bracket_end(part, i)
            if j > 0:
                out.append(("?",))
                i = j
            else:
                out.append(("c", "["))
                i += 1
        else:
            out.append(("c", c))
            i += 1
    return tuple(out)


def _meet(a, b):
    """True when some string matches both patterns (each a sequence of characters, '?' and '*')."""
    la, lb = len(a), len(b)
    seen, todo = set(), [(0, 0)]
    while todo:
        i, j = todo.pop()
        if (i, j) in seen:
            continue
        seen.add((i, j))
        if i == la and j == lb:
            return True
        ta = a[i] if i < la else None
        tb = b[j] if j < lb else None
        if ta == ("*",):
            todo.append((i + 1, j))                       # the star matches nothing more
            if tb is not None and tb != ("*",):
                todo.append((i, j + 1))                   # the star takes b's next character
        if tb == ("*",):
            todo.append((i, j + 1))
            if ta is not None and ta != ("*",):
                todo.append((i + 1, j))
        if ta is not None and tb is not None and ta != ("*",) and tb != ("*",):
            if ta[0] == "?" or tb[0] == "?" or ta[1] == tb[1]:
                todo.append((i + 1, j + 1))
    return False


def _could_be(part, name):
    """True when the path part (a glob or not) can be the exact name."""
    g = _glob(part)
    if g is None:
        return part == name
    return len(part) > _MAX_GLOB or _meet(g, _pattern(name))


def _secret_literal(low):
    if low.startswith(".env") or low in (".netrc", ".pgpass", "credentials") or low.startswith("credentials."):
        return True
    if low in _SECRET_DIRS:
        return True
    for e in _KEY_EXTS:
        i = low.find("." + e)
        while i >= 0:
            rest = low[i + 1 + len(e):]
            if rest == "" or rest[0] in _SUFFIX_SEPS:
                return True
            i = low.find("." + e, i + 1)
    for k in _KEY_NAMES:
        if low.startswith("id_" + k) and (len(low) == 3 + len(k) or low[3 + len(k)] in _SUFFIX_SEPS):
            return True
    return False


def _secret_part(part):
    if not part:
        return False
    low = part.lower()
    g = _glob(low)
    if g is None:
        return _secret_literal(low)
    if len(low) > _MAX_GLOB:
        return True
    return any(_meet(g, p) for p in _SECRET_PATTERNS)


def _expand_braces(word, depth=0):
    """a{b,c}d -> [abd, acd] (simple, non-nested braces; at most 64 results)."""
    if depth > 4:
        return [word]
    start = end = -1
    i = word.find("{")
    while i >= 0:
        j = i + 1
        while j < len(word) and word[j] not in "{}":
            j += 1
        if j < len(word) and word[j] == "}" and "," in word[i + 1:j]:
            start, end = i, j
            break
        i = word.find("{", i + 1)
    if start < 0:
        return [word]
    out = []
    for part in word[start + 1:end].split(","):
        out += _expand_braces(word[:start] + part + word[end + 1:], depth + 1)
        if len(out) > 64:
            break
    return out[:64]


def _drop(s, chars):
    return "".join(c for c in s if c not in chars)


def _unquoted(s):
    return _drop(s, "\"'\\`")


def _percent_decoded(s):
    """%-escapes decoded as UTF-8 (invalid bytes replaced); a `%` not followed by two hex digits stays."""
    if "%" not in s:
        return s
    out, raw, i = [], [], 0
    while i < len(s):
        if s[i] == "%" and i + 2 < len(s) and s[i + 1] in _HEX and s[i + 2] in _HEX:
            raw.append(int(s[i + 1:i + 3], 16))
            i += 3
            continue
        if raw:
            out.append(bytes(raw).decode("utf-8", "replace"))
            raw = []
        out.append(s[i])
        i += 1
    if raw:
        out.append(bytes(raw).decode("utf-8", "replace"))
    return "".join(out)


def _split_parts(w):
    parts, cur = [], []
    for c in w:
        if c in _PART_BREAKS or c.isspace():
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return [p for p in parts if p]


def _secret_word(word):
    forms = {_unquoted(word), _drop(word, "\"'`").replace("\\", "/")}
    forms |= {_percent_decoded(f) for f in forms}
    forms |= {_brackets_as_any(f) for f in forms if "[" in f}
    for w in (x for f in forms for x in _expand_braces(f)):
        parts = [p.lower() for p in _split_parts(w)]
        if any(_secret_part(p) for p in parts):
            return True
        if any(_could_be(a, ".config") and _could_be(b, "gcloud") for a, b in zip(parts, parts[1:])):
            return True
    return False


def _tokens(s):
    """Shell words and runs of the operators ;&|()<>, read as a POSIX shell would quote them; None when a quote is
    not closed or the text ends in a backslash."""
    s = s.replace("\n", " ; ")
    out, word, in_word, punct = [], [], False, []
    i, n = 0, len(s)

    def end_word():
        nonlocal word, in_word
        if in_word:
            out.append("".join(word))
        word, in_word = [], False

    def end_punct():
        nonlocal punct
        if punct:
            out.append("".join(punct))
        punct = []

    while i < n:
        c = s[i]
        if c in _SPACE:
            end_word()
            end_punct()
            i += 1
        elif c in _PUNCT:
            end_word()
            punct.append(c)
            i += 1
        else:
            end_punct()
            in_word = True
            if c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    return None
                word.append(s[i + 1:j])
                i = j + 1
            elif c == '"':
                i += 1
                while True:
                    if i >= n:
                        return None
                    if s[i] == '"':
                        i += 1
                        break
                    if s[i] == "\\" and i + 1 < n and s[i + 1] in '"\\':
                        word.append(s[i + 1])
                        i += 2
                    else:
                        word.append(s[i])
                        i += 1
            elif c == "\\":
                if i + 1 >= n:
                    return None
                word.append(s[i + 1])
                i += 2
            else:
                word.append(c)
                i += 1
    end_word()
    end_punct()
    return out


def _segments(tokens):
    seg = []
    for t in tokens:
        if t in _SEPARATORS or (t and all(c in _PUNCT for c in t)):
            if seg:
                yield seg
            seg = []
        else:
            seg.append(t)
    if seg:
        yield seg


def _program(word):
    return _unquoted(word).lstrip("$(").split("/")[-1].lower()


def _recursive_flag(a):
    """-r, -R, -rf, -fr, -dRf ... (a short option cluster holding r or R)."""
    return len(a) >= 2 and a[0] == "-" and all(c in _LETTERS for c in a[1:]) and ("r" in a or "R" in a)


def _hard(x):
    return len(x) >= 3 and "--hard".startswith(x)


def _destructive_argv(words):
    """True when an argument vector runs a destructive command anywhere in it (after a wrapper such as sudo)."""
    words = [_unquoted(w).strip("`") for w in words]
    for i, w in enumerate(words):
        prog = _program(w)
        rest = words[i + 1:]
        if prog == "rm":
            for a in rest:
                if _recursive_flag(a) or (len(a) >= 3 and "--recursive".startswith(a)) or a.startswith("--recursive="):
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
                if sub == "reset" and any(_hard(x) for x in rest[j + 1:]):
                    return True
                break
        elif prog == "reset" and any(_hard(x) for x in rest):
            return True                                   # a wrapper or alias of git (`g reset --hard`)
    return False


def _split_substitutions(tok):
    """The pieces of a word around `$(` and backticks."""
    out, cur, i = [], [], 0
    while i < len(tok):
        if tok.startswith("$(", i) or tok[i] == "`":
            out.append("".join(cur))
            cur = []
            i += 2 if tok[i] == "$" else 1
        else:
            cur.append(tok[i])
            i += 1
    out.append("".join(cur))
    return [p for p in out if p]


def _destructive_text(s, depth=0):
    if depth > 4:
        return False
    toks = _tokens(s)
    if toks is None:                                      # unbalanced quotes: judge the words without them
        toks = _tokens(_unquoted(s)) or _unquoted(s).split()
    toks = [t for tok in toks for t in _split_substitutions(tok)]
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
    """True when value names a secret path (the secret class above, globs included)."""
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
