"""kit_guard: the harness kit's guard helper (version 1, harness-marketplace 1.4.4). Standard library only.

    import kit_guard

    def run(command: str) -> str:
        if kit_guard.refuses(command):
            return "refused: secret path or destructive command"
        return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

refuses(value) is True when value names a secret path (.env files, keys, credential folders) or a destructive command
(git push, git reset --hard, git clean, rm with a recursive flag) anywhere in it. value may be a string (a command or a
path) or a tool's whole input (a dict or a list): every string inside it is checked on its own, keys included.

harness-audit credits `if kit_guard.refuses(<the tool's own input>): <refuse>` as a canonical guard only while this
file is byte for byte the shipped one: its sha256 is pinned in the audit. Copy it unchanged. To refuse more, add your
own canonical `if` beside it instead of editing this file.
"""
from __future__ import annotations

import re

SECRET = re.compile(r"\.env\b|\.pem\b|\.key\b|\.p12\b|\.pfx\b|\.ssh\b|\.aws\b|\.gnupg\b|\.netrc\b|"
                    r"\bid_(rsa|dsa|ecdsa|ed25519)\b|credentials", re.I)
DESTRUCTIVE = re.compile(r"\bgit\s+push\b|\bgit\s+reset\s+--hard\b|\bgit\s+clean\b|"
                         r"\brm\s+(-{1,2}\S*\s+)*-{1,2}([a-zA-Z]*[rR][a-zA-Z]*|recursive)\b")


def _strings(value, depth=0):
    """Every string inside value (dict keys and values, list items), each on its own."""
    if isinstance(value, str):
        yield value
    elif depth > 20:
        yield str(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k, depth + 1)
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for v in value:
            yield from _strings(v, depth + 1)
    elif value is not None:
        yield str(value)


def refuses(value) -> bool:
    """True when value names a secret path or a destructive command."""
    return bool(any(SECRET.search(s) or DESTRUCTIVE.search(s) for s in _strings(value)))
