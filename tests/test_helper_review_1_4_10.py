"""The independent helper-side review of 1.4.10 before packaging (about 2,260 inputs, 11 tool calls, the written
docstring as the specification, harmless stand-ins only). Each case below is one the reviewer reported; the reviewer's
case number is in the comment. Case 9 (`echo git push` refused) follows the docstring's "wherever the program
appears" and is not changed (DECISIONS.md)."""
import unittest

from test_audit_r9 import KG


def nested(d, kind=list):
    v = "hello"
    for _ in range(d):
        v = [v] if kind is list else {"k": v}
    return v


class HelperReview1410(unittest.TestCase):
    def test_1_more_than_20_containers_is_refused(self):
        for kind in (list, dict):
            self.assertFalse(KG.refuses(nested(20, kind)))
            self.assertTrue(KG.refuses(nested(21, kind)))

    def test_2_brace_limits_are_per_word_not_per_value(self):
        for v in ("echo {1..9} {1..9}", "echo {1..9}; echo {1..9}", "echo {a,b} {c,d}; echo {e,f} {g,h}; echo {i,j}",
                  "echo {a,b,c} {d,e,f} {g,h,i} {j,k,l}", "echo {a,b,c,d,e,f,g,h,i} {1..8}"):
            with self.subTest(v=v):
                self.assertFalse(KG.refuses(v))
        self.assertTrue(KG.refuses("cat {a,b,c,d,e,f,g,h,i}{1..8}"))       # one word past 64 stays refused
        self.assertTrue(KG.refuses("cat {x,.env} {1..9}"))                  # a member in one word is still read

    def test_3_env_split_string_underscore_separator(self):
        for v in ("env -S'git\\_push'", "env -S 'git\\_push'", 'env -S"git\\_push"', "env -S'rm\\_-rf\\_x'",
                  "env -S'cat\\_.env'", "env --split-string=git\\_push"):
            with self.subTest(v=v):
                self.assertTrue(KG.refuses(v))

    def test_4_s_inside_a_short_option_cluster(self):
        for v in ("env -vS'git push'", "env -iS'git push'", "env -u X -vS'git push'"):
            with self.subTest(v=v):
                self.assertTrue(KG.refuses(v))

    def test_5_split_string_abbreviations(self):
        for v in ("env --split='git push'", "env --spl='git push'", "env --split-str='git push'", "env --s='git push'"):
            with self.subTest(v=v):
                self.assertTrue(KG.refuses(v))

    def test_6_git_options_taking_a_separate_value(self):
        for v in ("git --attr-source HEAD push", "git --shallow-file x push"):
            with self.subTest(v=v):
                self.assertTrue(KG.refuses(v))

    def test_7_a_glob_in_the_program_word(self):
        for v in ("/usr/bin/gi? push", "/usr/bin/gi[t] push", "/bin/r[m] -rf x", "/bin/r? -rf x", "g* push"):
            with self.subTest(v=v):
                self.assertTrue(KG.refuses(v))
        for v in ("l? -la", "/bin/ech? hello"):
            with self.subTest(v=v):
                self.assertFalse(KG.refuses(v))

    def test_8_a_secret_attached_to_a_short_option(self):
        for v in ("tar -f.env", "ssh -iid_rsa host", "curl -K.netrc u"):
            with self.subTest(v=v):
                self.assertTrue(KG.refuses(v))
        self.assertFalse(KG.refuses("ls -la"))

    def test_10_nesting_counts_from_an_argument_vector_too(self):
        s = "echo hi"
        for _ in range(4):
            s = "sh -c '" + s.replace("'", "'\\''") + "'"
        self.assertTrue(KG.refuses(["sh", "-c", s]))
        s3 = "echo hi"
        for _ in range(3):
            s3 = "sh -c '" + s3.replace("'", "'\\''") + "'"
        self.assertFalse(KG.refuses(["sh", "-c", s3]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
