"""Tests for group_release_notes.py.

Run from the repository root:
python3 -m unittest discover -s .github/scripts -p 'test_*.py'
"""
import unittest

from group_release_notes import OTHER, classify, group


def entry(title, number=1):
    url = f"https://github.com/camunda/camunda-security-library/pull/{number}"
    return f"* {title} by @alice in {url}"


class ClassifyTest(unittest.TestCase):
    def assert_section(self, title, section):
        self.assertEqual(classify(entry(title)), section, title)

    def test_type_selects_section(self):
        self.assert_section("feat: add policy model", "Features")
        self.assert_section("fix(oidc): handle expired token", "Bug fixes")
        self.assert_section("perf: cache scopes", "Performance")
        self.assert_section("refactor: split service", "Refactoring")
        self.assert_section("docs: update ADR index", "Documentation")
        self.assert_section("test: cover snapshot apply", "Tests")
        self.assert_section("ci: pin actions", "Build and CI")
        self.assert_section("build: bump maven plugin", "Build and CI")
        self.assert_section("chore: tidy imports", "Maintenance")

    def test_type_is_case_insensitive(self):
        self.assert_section("Fix: handle null", "Bug fixes")

    def test_bang_marks_breaking_change(self):
        self.assert_section("feat(api)!: remove legacy port", "Breaking changes")
        self.assert_section("refactor!: rename port", "Breaking changes")

    def test_bang_wins_over_deps_scope(self):
        self.assert_section("fix(deps)!: drop java 17", "Breaking changes")

    def test_deps_scope_selects_dependency_updates(self):
        self.assert_section("fix(deps): update spring boot", "Dependency updates")
        self.assert_section("chore(deps): update actions", "Dependency updates")

    def test_unknown_type_goes_to_other(self):
        self.assert_section("wip: try something", OTHER)

    def test_non_conventional_title_goes_to_other(self):
        self.assert_section("Update README.md", OTHER)


NOTES = "\n".join(
    [
        "## What's Changed",
        entry("chore: tidy imports", 1),
        entry("feat: add policy model", 2),
        entry("Update README.md", 3),
        entry("feat(api)!: remove legacy port", 4),
        entry("fix(deps): update spring boot", 5),
        "",
        "## New Contributors",
        "* @bob made their first contribution in https://example.com/6",
        "",
        "**Full Changelog**: https://example.com/compare/1.2.2...1.3.0",
        "",
    ]
)


class GroupTest(unittest.TestCase):
    def test_notes_without_whats_changed_stay_unchanged(self):
        notes = "Nothing to group\n"
        self.assertEqual(group(notes), notes)

    def test_sections_follow_the_defined_order(self):
        headings = [line for line in group(NOTES).splitlines() if line.startswith("### ")]
        self.assertEqual(
            headings,
            [
                "### Breaking changes",
                "### Features",
                "### Dependency updates",
                "### Maintenance",
                "### Other changes",
            ],
        )

    def test_no_entry_is_lost(self):
        def entries(notes):
            return sorted(line for line in notes.splitlines() if line.startswith("* "))

        self.assertEqual(entries(group(NOTES)), entries(NOTES))

    def test_later_sections_stay_after_the_groups(self):
        lines = group(NOTES).splitlines()
        self.assertLess(lines.index("### Other changes"), lines.index("## New Contributors"))
        self.assertEqual(lines[-1], "**Full Changelog**: https://example.com/compare/1.2.2...1.3.0")

    def test_adds_no_contributors_section(self):
        self.assertNotIn("## Contributors", group(NOTES))


if __name__ == "__main__":
    unittest.main()
