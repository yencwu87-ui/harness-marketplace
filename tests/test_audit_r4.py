"""Codex round-4 findings on 1.4.4 (R4-01 to R4-09), written as the invariant the audit must hold from 1.4.5 on.

1.4.5 narrows what can earn credit: a code refusal earns points only through the kit's own guard helper in one exact
call shape, or through a framework's exact documented contract (`CANONICAL_FORMS`, `audit.py --canonical-forms`).
Hand-written predicates are UNRESOLVED with a named reason. The helper defines the classes it covers.

Fixtures under tests/fixtures/codex_r4 come from Codex's round-4 review of 1.4.4 (see its README).
"""
import importlib.util
import unittest

from test_audit_fairness import GUARD, ROOT, Repo, audit, guards, points

FIX = ROOT / "tests/fixtures/codex_r4"
KIT_GUARD = ROOT / "kit/shared/kit_guard.py"


def statuses(rep):
    return tuple(guards(rep)[c]["status"] for c in GUARD)


def load_kit_guard(path=KIT_GUARD):
    spec = importlib.util.spec_from_file_location("kit_guard_r4", path)
    kg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kg)
    return kg


class R4Fixtures(unittest.TestCase):
    """Every R4 fixture whose guard does not stop the call loses all G1-G3 credit."""

    def no_credit(self, *names):
        for name in names:
            with self.subTest(fixture=name):
                rep = audit(FIX / name)
                self.assertEqual(points(rep), 0, guards(rep))
                self.assertNotIn("VERIFIED", statuses(rep))

    def test_r4_01_rebound_trusted_names(self):
        self.no_credit("regex_alias_shadow", "regex_from_shadow", "kit_function_param", "kit_alias_shadow")

    def test_r4_02_the_tested_value_is_not_the_operation_argument(self):
        self.no_credit("wrong_capability_argument")

    def test_r4_03_exits_inside_a_tool_scope_branch(self):
        self.no_credit("scoped_exit_adk", "scoped_exit_crew", "scoped_exit_strands", "scoped_exit_maf")

    def test_r4_04_input_changed_through_an_alias(self):
        self.no_credit("input_alias_crew", "input_alias_sdk", "input_alias_adk")

    def test_r4_05_strands_cancel_on_another_object_or_undone(self):
        self.no_credit("cancel_wrong_object", "cancel_overwritten_augassign")

    def test_r4_06_sdk_deny_outside_the_documented_shape(self):
        self.no_credit("sdk_wrong_output_key", "sdk_top_level_decision", "sdk_helper_fallthrough",
                       "sdk_helper_decorator", "sdk_helper_early_allow", "sdk_attr_field")

    def test_r4_07_one_keyword_does_not_earn_a_class(self):
        self.no_credit("representative_only")

    def test_r4_08_the_old_helper_is_no_longer_trusted(self):
        """kit_unchanged carries the 1.4.4 helper byte for byte; it misses `.env_*` and `reset --quiet --hard`."""
        self.no_credit("kit_unchanged")

    def test_r4_09_filesystem_isolation_disabled(self):
        off = guards(audit(FIX / "native_fs_off"))
        self.assertNotEqual(off["G2"]["status"], "VERIFIED", off["G2"])
        self.assertIn("filesystem", off["G2"]["evidence"])
        on = audit(FIX / "native_fs_on")
        self.assertEqual(points(on), 8, guards(on))


class R4_08_HelperRefusesTheReportedInputs(unittest.TestCase):
    def test_the_two_reported_inputs(self):
        kg = load_kit_guard()
        for s in ("cat /constructed/.env_constructed", "git reset --quiet --hard"):
            with self.subTest(value=s):
                self.assertTrue(kg.refuses(s))


class R4_09_FilesystemIsolation(unittest.TestCase):
    BASE = ('{"permissions": {"allow": ["Bash(*)"], "deny": ["Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", '
            '"WebSearch", "Read", "Grep", "Glob", "Read(**/.env*)", "Bash(git push *)", "Bash(rm -rf *)"]}, '
            '"sandbox": {"enabled": true, "allowUnsandboxedCommands": false%s}}')

    def g2(self, extra):
        with Repo({".claude/settings.json": self.BASE % extra}) as d:
            return guards(audit(d))["G2"]["status"]

    def test_disabled_true_loses_the_read_deny_binding(self):
        self.assertEqual(self.g2(''), "VERIFIED")
        self.assertEqual(self.g2(', "filesystem": {"disabled": false}'), "VERIFIED")
        self.assertNotEqual(self.g2(', "filesystem": {"disabled": true}'), "VERIFIED")
        self.assertNotEqual(self.g2(', "filesystem": {"disabled": true}, "failIfUnavailable": true'), "VERIFIED")
        self.assertNotEqual(self.g2(', "filesystem": {"disabled": "yes"}'), "VERIFIED")   # not readable as false


if __name__ == "__main__":
    unittest.main(verbosity=2)
