"""kit_guard: the harness kit's guard helper (version 7, harness-marketplace 1.4.10). It imports nothing.

    import subprocess
    from kit_guard import refuses

    def run(command: str) -> str:
        if refuses(command):
            return "refused: secret path or destructive command"
        return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

refuses(value) is True when value names a secret path or is a destructive command. value may be a string (a command,
a path or a URL) or a tool's whole input (a dict or a list): every string inside it is checked on its own, keys
included, and a list of strings is also checked as one argument vector (`['rm', '-rf', 'x']`). A string inside more
than 20 containers (dicts and lists) is refused.

Before any other step, every string is also read with each backslash-newline pair removed, as the shell removes a
line continuation (outside single quotes, inside double quotes too), and with every such pair removed wherever it is;
the value is refused when any of these forms (the unjoined one included) is refused.

The classes, as this helper defines them (harness-audit credits exactly these):
  secret       a path part named .env or starting with .env (.env.local, .env_prod, .envrc); ending in .pem, .key,
               .p12 or .pfx, or holding one of those followed by `.`, `_`, `~` or `-` and anything (server.key.bak);
               id_rsa, id_dsa, id_ecdsa or id_ed25519, alone or followed by `.`, `_`, `~` or `-` and anything (.pub,
               .bak); .netrc; .pgpass; credentials or credentials.<anything>; or inside .ssh, .aws, .gnupg, .azure,
               .kube, .docker or .config/gcloud, also attached to a short option (`-f.env`, `-iid_rsa`). Upper and
               lower case are the same. Read after shell quotes and
               backslashes are removed (or read as Windows separators), %-escapes decoded (up to three times, so
               %252e is a dot; a value still encoded after the third time is refused), simple braces expanded (`{a,b}` and sequences `{a..e}`, `{1..9}`; a word with more
               than four brace groups, more than 64 expansions or a sequence of more than 256 items is refused),
               and `.` and `..` path parts resolved.
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
               --ha included (and `reset --hard` after any program); git -c alias.*=... or --config-env alias.*=...
               (an alias can run anything); rm with a recursive option in any position (-r, -R, -rf, -fr, -r -f,
               --recursive and its abbreviations, rm x -rf). Brace groups are expanded first, as for secrets
               (`git {push,status}`, `r{m,x} -rf x`, `{git,push}`): the command is refused when any word read as
               one of its expansions, or as all of them in a row, gives a destructive command; more than four
               braced words, a group past the limits above, or more than 256 readings is refused, and so is a word
               holding an unquoted `{` and a quoted or escaped `{` or `}` (`git pu{sh,'}'}`). Each reading's words
               are also read as nested shells (`bash -c {'git push',x}`), and so is the string `env -S` carries
               (also in a cluster such as `-vS`, after `--split-string=` or any abbreviation of it, and with env's
               `\\_` read as a space); an argument vector's items start one level down (`['sh', '-c', ...]`). A
               program word holding a glob is read as git, rm or reset when it could expand to one (`/usr/bin/gi?`). Nested shells are read four levels deep: a word holding anything but
               letters, digits and ._/:=@%+,-~^ (a space, a TAB, a newline, one of ;&|()<>, a quote, a brace, `$`
               or a backtick) is read again as a command; a command nested deeper is not read, so it is refused,
               benign or not, and counts as secret too (`sh -c` five times around anything with a space).
  blanks       words are split on a space, a TAB and a newline (a CR before a newline is read with it), and
               commands on a newline and ; & | ( ). Any other control character (U+0000 to U+001F, U+007F to
               U+009F) or a non-ASCII space (U+00A0, U+2000 to U+200B, U+3000, U+FEFF, ...) anywhere in a value
               is refused, benign or not, and counts as secret too.
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
                        "--config-env", "--list-cmds", "--attr-source", "--shallow-file"}
_MAX_GLOB = 256
_MAX_SEQUENCE = 256          # items one brace sequence ({1..9}) may stand for; a longer one is refused
_PERCENT_ROUNDS = 3          # %-decodings read; a value still encoded after them is refused
_MAX_CONTAINERS = 20         # dicts and lists nested in a tool input; a deeper value is refused
_PLAIN_WORD = frozenset(_LETTERS + "0123456789._/:=@%+,-~^")   # a nested word of only these is not read again
_ODD_SPACES = frozenset("\u200b\u2060\ufeff\u180e")   # spaces that are not isspace() but read as one


def _odd_char(s):
    """True when s holds a character the helper does not read as a shell would: a control character other than a
    TAB or a newline (a CR before a newline is read with the newline), or a non-ASCII space."""
    for i, c in enumerate(s):
        o = ord(c)
        if o < 32 and c not in "\t\n" and not (c == "\r" and s[i + 1:i + 2] == "\n"):
            return True
        if 127 <= o < 160 or (o > 127 and (c.isspace() or c in _ODD_SPACES)):
            return True
    return False


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


def _sequence(inner):
    """The items of a brace sequence `a..e` or `1..3` (a step is ignored: a superset); None when inner is not a
    sequence, False when it is one of more than _MAX_SEQUENCE items (refused)."""
    parts = inner.split("..")
    if len(parts) not in (2, 3):
        return None
    a, b = parts[0], parts[1]
    if len(a) == 1 and len(b) == 1 and not (a + b).lstrip("-").isdigit():
        lo, hi = sorted((ord(a), ord(b)))
        return [chr(c) for c in range(lo, hi + 1)] if hi - lo < _MAX_SEQUENCE else False
    try:
        lo, hi = sorted((int(a), int(b)))
    except ValueError:
        return None
    return [str(i) for i in range(lo, hi + 1)] if hi - lo < _MAX_SEQUENCE else False


def _expand_braces(word, depth=0):
    """a{b,c}d -> [abd, acd], and a{1..3} -> [a1, a2, a3] (non-nested braces); None when the word holds more than
    four brace groups or expands to more than 64 words, which the caller refuses (fail closed)."""
    if depth > 4:
        return None
    start = end = -1
    items = None
    i = word.find("{")
    while i >= 0:
        j = i + 1
        while j < len(word) and word[j] not in "{}":
            j += 1
        if j < len(word) and word[j] == "}":
            inner = word[i + 1:j]
            items = inner.split(",") if "," in inner else _sequence(inner)
            if items is False:
                return None                             # a sequence too long to read: refused
            if items is not None:
                start, end = i, j
                break
        i = word.find("{", i + 1)
    if start < 0:
        return [word]
    out = []
    for part in items:
        more = _expand_braces(word[:start] + part + word[end + 1:], depth + 1)
        if more is None:
            return None
        out += more
        if len(out) > 64:
            return None
    return out


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


def _normalised(parts):
    """Path parts with `.` dropped and `..` taken back (`.config/x/../gcloud` -> `.config/gcloud`)."""
    out = []
    for p in parts:
        if p == "..":
            if out:
                out.pop()
        elif p != ".":
            out.append(p)
    return out


def _secret_word(word, whole=False):
    """word names a secret. `whole` is the value read as one word: its brace limits are each word's, so past them
    it is read with the braces dropped (each word is also read on its own, with them)."""
    forms = {_unquoted(w) for w in {word, word.replace("\\_", " ")}} | {_drop(word, "\"'`").replace("\\", "/")}
    forms |= {f[2:] for f in forms if f[:1] == "-" and f[1:2] not in ("-", "") and len(f) > 2}   # -f.env, -iid_rsa
    last = set(forms)
    for _ in range(_PERCENT_ROUNDS):                    # %252e -> %2e -> .
        last = {_percent_decoded(f) for f in last}
        forms |= last
    if any(_percent_decoded(f) != f for f in last):
        return True                                     # still encoded past the bound: refused
    forms |= {_brackets_as_any(f) for f in forms if "[" in f}
    expanded = [_expand_braces(f) for f in forms]
    if None in expanded:
        if not whole:
            return True                                 # too many brace groups or words to read: refused
        expanded = [[_drop(f, "{}")] for f in forms]
    for w in (x for e in expanded for x in e):
        parts = [p.lower() for p in _split_parts(w)]
        if any(_secret_part(p) for p in parts):
            return True
        for seq in (parts, _normalised(parts)):
            if any(_could_be(a, ".config") and _could_be(b, "gcloud") for a, b in zip(seq, seq[1:])):
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
        if _glob(prog) is not None:                     # /usr/bin/gi? : the shell may expand it to git
            prog = next((n for n in ("git", "rm", "reset") if _could_be(prog, n)), prog)
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
                    if a in ("-c", "--config-env") and j + 1 < len(rest) and rest[j + 1].lower().startswith("alias."):
                        return True
                    j += 2
                    continue
                if a.startswith("-"):
                    if a.lower().startswith(("-calias.", "--config-env=alias.")):
                        return True
                    if a.startswith("--") and "=" not in a and j + 2 < len(rest) and rest[j + 2].lower() in ("push", "clean"):
                        return True                       # an unknown long option may take the next word as its value
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


_MAX_BRACE_WORDS = 4         # words in one command that hold a brace group
_MAX_BRACE_READINGS = 256    # argument vectors one command's braces may be read as


def _brace_readings(words):
    """The argument vectors a command's brace groups may stand for: each word with a group replaced by each of its
    expansions on its own, or by all of them in a row (as the shell does: `{git,push}` is `git push`). None when the
    words hold too many groups, a group expands too far or nests too deep, or the readings are too many (refused)."""
    choices, braced = [], 0
    for w in words:
        alts = _expand_braces(w) if "{" in w else [w]
        if alts is None:
            return None
        if len(alts) > 1:
            braced += 1
            choices.append([[a] for a in alts] + [alts])
        else:
            choices.append([alts])
    if braced == 0:
        return [list(words)]
    if braced > _MAX_BRACE_WORDS:
        return None
    readings = [[]]
    for c in choices:
        readings = [r + x for r in readings for x in c]
        if len(readings) > _MAX_BRACE_READINGS:
            return None
    return readings


def _destructive_braced(words):
    """True when any reading of the words' brace groups is destructive, or when they are too many to read."""
    readings = _brace_readings(words)
    return readings is None or any(_destructive_argv(r) for r in readings)


def _mixed_braces(s):
    """True when a shell word holds an unquoted `{` and also a quoted or escaped `{` or `}`: the shell may expand a
    group the helper cannot pair (`git pu{sh,'}'}` is `git push pu}`), so the word is refused (fail closed)."""
    quote, open_brace, quoted_brace, i, n = None, False, False, 0, len(s)
    while i < n:
        c = s[i]
        if quote == "'":
            quoted_brace = quoted_brace or c in "{}"
            quote = None if c == "'" else quote
        elif c == "\\" and i + 1 < n:
            quoted_brace = quoted_brace or s[i + 1] in "{}"
            i += 1
        elif c == '"':
            quote = None if quote == '"' else '"'
        elif quote == '"':
            quoted_brace = quoted_brace or c in "{}"
        elif c == "'":
            quote = "'"
        elif c in _SPACE or c in _PUNCT:
            if open_brace and quoted_brace:
                return True
            open_brace = quoted_brace = False
        elif c == "{":
            open_brace = True
        i += 1
    return open_brace and quoted_brace


_MAX_NESTING = 4             # nested shells (bash -c '...') read; a deeper one is not read, so it is refused


class _Unread(Exception):
    """A nested command past a bound the helper reads to: refused as destructive and secret-bearing (fail closed)."""


def _carried(w):
    """The texts a word may hand a nested shell: the word itself; what `env -S` carries, also inside a cluster of
    short options (`-vS'...'`) and after --split-string= or any abbreviation of it (`--split=`); each also with env's
    `\\_` read as a space."""
    out = [w]
    if w[:1] == "-" and w[1:2] != "-":
        i = w.find("S")
        if i > 0 and all(c in _LETTERS for c in w[1:i]):
            out.append(w[i + 1:])
    elif w.startswith("--s") and "=" in w and "--split-string".startswith(w.split("=", 1)[0]):
        out.append(w.split("=", 1)[1])
    return out + [t.replace("\\_", " ") for t in out if "\\_" in t]


def _destructive_text(s, depth=0):
    """A nested shell (bash -c '...') joins its own continued lines, so each level reads every continuation form.
    A nested command past _MAX_NESTING is not read: it raises _Unread, and the value is refused."""
    if depth > _MAX_NESTING:
        raise _Unread
    return any(_destructive_form(f, depth) for f in _continuations(s))


def _destructive_form(s, depth):
    toks = _tokens(s)
    if toks is None:                                      # unbalanced quotes: judge the words without them
        toks = _tokens(_unquoted(s)) or _unquoted(s).split()
    if _mixed_braces(s):
        return True
    toks = [t for tok in toks for t in _split_substitutions(tok)]
    for seg in _segments(toks):
        readings = _brace_readings(seg)
        if readings is None:
            return True
        for words in [seg] + readings:                     # the words as written, and each brace reading
            if _destructive_argv(words):
                return True
            for w in words:                                # bash -c "...", sh -c '...', eval "...", env -S'...'
                for text in _carried(w):
                    if text and text != s and any(c not in _PLAIN_WORD for c in text) and \
                            _destructive_text(text, depth + 1):     # a word equal to s is s, already read
                        return True
    return False


def _joined(s):
    """s with each backslash-newline pair removed as the shell removes a line continuation: outside single quotes
    and inside double quotes; a backslash that quotes any other character stays with it."""
    out, i, n, quote = [], 0, len(s), None
    while i < n:
        c = s[i]
        if quote == "'":
            out.append(c)
            quote = None if c == "'" else quote
            i += 1
        elif c == "\\" and i + 1 < n:
            if s[i + 1] != "\n":
                out.append(s[i:i + 2])
            i += 2
        else:
            if c == "'" and quote is None:
                quote = "'"
            elif c == '"':
                quote = None if quote == '"' else '"'
            out.append(c)
            i += 1
    return "".join(out)


def _unjoined(s):
    return s


def _all_pairs_removed(s):
    return s.replace("\\\r\n", "").replace("\\\n", "")


_JOINS = (_unjoined, _joined, _all_pairs_removed)


def _continuations(s):
    """s, s joined as the shell would, and s with every backslash-newline pair removed wherever it is (fail closed)."""
    if "\\\n" not in s and "\\\r\n" not in s:
        return [s]
    return list(dict.fromkeys(f(s) for f in _JOINS))


def _forms(value):
    """Every string and argument vector of value (as _strings yields them), each also in its continuation forms."""
    for s in _strings(value):
        if any(_odd_char(x) for x in (s if isinstance(s, tuple) else (s,))):
            raise _Unread                               # a control character or an odd space: refused
        if isinstance(s, tuple):
            yield from dict.fromkeys(tuple(f(x) for x in s) for f in _JOINS)
        else:
            yield from _continuations(s)


def _strings(value, depth=0):
    """Every string inside value (dict keys and values, list items), each on its own; a list of strings is also
    yielded as one argument vector (a tuple)."""
    if depth > _MAX_CONTAINERS:
        raise _Unread                                   # nested past the bound: refused
    if isinstance(value, str):
        yield value
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


def _secret(value):
    for s in _forms(value):
        words = list(s) if isinstance(s, tuple) else _tokens(s) or []
        if any(_secret_word(w) for w in words) or (not isinstance(s, tuple) and _secret_word(s, whole=True)):
            return True
    return False


def _destructive(value):
    for s in _forms(value):
        if _destructive_braced(list(s)) if isinstance(s, tuple) else _destructive_text(s):
            return True
        if isinstance(s, tuple) and any(_destructive_text(x, 1) for x in s[1:]):
            return True                                 # ['sh', '-c', <nested>]: <nested> is one level down
    return False


def _unread(value):
    """True when value holds a nested command past the bound the helper reads to."""
    try:
        _destructive(value)
    except (_Unread, RecursionError):
        return True
    return False


def secret(value) -> bool:
    """True when value names a secret path (the secret class above, globs included), or holds a nested command the
    helper does not read."""
    try:
        return _secret(value) or _unread(value)
    except (_Unread, RecursionError):
        return True


def destructive(value) -> bool:
    """True when value is a destructive command (the destructive class above), or holds a nested command the helper
    does not read."""
    try:
        return _destructive(value)
    except (_Unread, RecursionError):
        return True


def refuses(value) -> bool:
    """True when value names a secret path or is a destructive command (an unread nested command is both)."""
    try:
        return _secret(value) or destructive(value)
    except (_Unread, RecursionError):
        return True
