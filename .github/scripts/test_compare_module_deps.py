"""Unit tests for the comparison logic in compare-module-deps.py.

Covers the pure functions only; resolving classpaths needs Maven and Gradle and is exercised by the
CI step that runs the script itself. Loaded via importlib because the script name has hyphens, as
in the monorepo's test_compare_module_deps.py (camunda/camunda#52869).

Run: python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v
"""

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("compare-module-deps.py")
SPEC = importlib.util.spec_from_file_location("compare_module_deps", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

LIBRARY = "com.example:library"
ALLOWED_EXTRA = "org.junit.platform:junit-platform-launcher"  # allowlisted for test scope only
ALLOWED_MISSING = "org.apiguardian:apiguardian-api"  # allowlisted for test scope only


def report(third_party=None, internal=()):
    return {"third_party": dict(third_party or {}), "internal": set(internal)}


def compare(scope, maven, gradle, gradle_runtime=None):
    return MODULE.compare(scope, maven, gradle, gradle_runtime or report())


class AllowedTest(unittest.TestCase):
    TABLE = {LIBRARY: ({"test"}, "reason")}

    def test_should_allow_listed_coordinate_in_listed_scope(self):
        self.assertTrue(MODULE.allowed(self.TABLE, "test", LIBRARY))

    def test_should_not_allow_listed_coordinate_in_other_scope(self):
        self.assertFalse(MODULE.allowed(self.TABLE, "compile", LIBRARY))

    def test_should_not_allow_unlisted_coordinate(self):
        self.assertFalse(MODULE.allowed(self.TABLE, "test", "com.example:other"))


class CompareTest(unittest.TestCase):
    def test_should_report_no_differences_for_identical_classpaths(self):
        maven = report({LIBRARY: "1.0.0"}, internal={"core"})
        gradle = report({LIBRARY: "1.0.0"}, internal={"core"})

        diff = compare("runtime", maven, gradle)

        for key in (
            "missing_in_gradle",
            "implementation_only",
            "extra_in_gradle",
            "version_mismatches",
            "internal_missing_in_gradle",
            "internal_extra_in_gradle",
        ):
            self.assertEqual(diff[key], [], key)
        self.assertEqual(diff["counts"], {"maven": 1, "gradle": 1})

    def test_should_report_dependency_missing_in_gradle(self):
        diff = compare("runtime", report({LIBRARY: "1.0.0"}), report())

        self.assertEqual(diff["missing_in_gradle"], [LIBRARY])

    def test_should_report_dependency_extra_in_gradle(self):
        diff = compare("runtime", report(), report({LIBRARY: "1.0.0"}))

        self.assertEqual(diff["extra_in_gradle"], [LIBRARY])

    def test_should_accept_compile_gap_when_gradle_resolves_it_at_runtime(self):
        diff = compare(
            "compile", report({LIBRARY: "1.0.0"}), report(), gradle_runtime=report({LIBRARY: "1.0.0"})
        )

        self.assertEqual(diff["missing_in_gradle"], [])
        self.assertEqual(diff["implementation_only"], [LIBRARY])

    def test_should_report_runtime_gap_even_when_gradle_runtime_has_it(self):
        # The implementation-only narrowing applies to the compile classpath only.
        diff = compare(
            "runtime", report({LIBRARY: "1.0.0"}), report(), gradle_runtime=report({LIBRARY: "1.0.0"})
        )

        self.assertEqual(diff["missing_in_gradle"], [LIBRARY])
        self.assertEqual(diff["implementation_only"], [])

    def test_should_report_version_mismatch(self):
        diff = compare("runtime", report({LIBRARY: "1.0.0"}), report({LIBRARY: "1.0.1"}))

        self.assertEqual(
            diff["version_mismatches"],
            [{"coordinate": LIBRARY, "maven": "1.0.0", "gradle": "1.0.1"}],
        )

    def test_should_ignore_allowlisted_extra_in_its_scope(self):
        diff = compare("test", report(), report({ALLOWED_EXTRA: "1.0.0"}))

        self.assertEqual(diff["extra_in_gradle"], [])

    def test_should_report_allowlisted_extra_outside_its_scope(self):
        diff = compare("compile", report(), report({ALLOWED_EXTRA: "1.0.0"}))

        self.assertEqual(diff["extra_in_gradle"], [ALLOWED_EXTRA])

    def test_should_ignore_allowlisted_missing_in_its_scope(self):
        diff = compare("test", report({ALLOWED_MISSING: "1.0.0"}), report())

        self.assertEqual(diff["missing_in_gradle"], [])

    def test_should_report_allowlisted_missing_outside_its_scope(self):
        diff = compare("runtime", report({ALLOWED_MISSING: "1.0.0"}), report())

        self.assertEqual(diff["missing_in_gradle"], [ALLOWED_MISSING])

    def test_should_report_internal_project_differences(self):
        diff = compare("runtime", report(internal={"api"}), report(internal={"core"}))

        self.assertEqual(diff["internal_missing_in_gradle"], ["api"])
        self.assertEqual(diff["internal_extra_in_gradle"], ["core"])


class FormatResultTest(unittest.TestCase):
    def test_should_pass_and_list_implementation_only_as_note(self):
        diff = compare(
            "compile", report({LIBRARY: "1.0.0"}), report(), gradle_runtime=report({LIBRARY: "1.0.0"})
        )

        ok, text = MODULE.format_result("core", "compile", diff)

        self.assertTrue(ok)
        self.assertIn("[ok  ] core / compile", text)
        self.assertIn(f"runtime-only in Gradle (implementation): {LIBRARY}", text)

    def test_should_fail_and_list_every_difference(self):
        maven = report({LIBRARY: "1.0.0", "com.example:gone": "1.0.0"}, internal={"api"})
        gradle = report({LIBRARY: "2.0.0", "com.example:new": "1.0.0"}, internal={"core"})

        ok, text = MODULE.format_result("core", "runtime", compare("runtime", maven, gradle))

        self.assertFalse(ok)
        self.assertIn("[DIFF] core / runtime", text)
        self.assertIn("MISSING in Gradle: com.example:gone", text)
        self.assertIn("EXTRA in Gradle: com.example:new", text)
        self.assertIn("MISSING internal project in Gradle: api", text)
        self.assertIn("EXTRA internal project in Gradle: core", text)
        self.assertIn(f"VERSION {LIBRARY}: maven=1.0.0 gradle=2.0.0", text)


if __name__ == "__main__":
    unittest.main()
