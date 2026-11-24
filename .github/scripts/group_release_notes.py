#!/usr/bin/env python3
"""Groups GitHub's generated release notes by Conventional Commits type.

GitHub can only group generated notes by PR label, and our PRs carry no type
labels. PR titles follow Conventional Commits, so this script groups the
"What's Changed" entries by the title prefix instead. It then adds a
"Contributors" section with every human author of the release. All other
sections (New Contributors, Full Changelog) stay as they are.

Usage: group_release_notes.py < generated-notes.md > grouped-notes.md
"""
import re
import sys

# Section order in the output, with the Conventional Commits types each one takes.
# "Breaking changes" and "Dependency updates" have no types: classify() fills them
# from the "!" marker and the "deps" scope.
SECTIONS = [
    ("Breaking changes", ()),
    ("Features", ("feat",)),
    ("Bug fixes", ("fix",)),
    ("Performance", ("perf",)),
    ("Refactoring", ("refactor",)),
    ("Documentation", ("docs",)),
    ("Tests", ("test",)),
    ("Dependency updates", ()),
    ("Build and CI", ("build", "ci")),
    ("Maintenance", ("chore", "style", "revert")),
]
OTHER = "Other changes"

# "* <type>(<scope>)!: <subject> by @user in <url>"
ENTRY = re.compile(r"^\* (?P<type>[A-Za-z]+)(?:\((?P<scope>[^)]*)\))?(?P<bang>!)?: ")
WHATS_CHANGED = "## What's Changed"
# The author block follows the last " by @": "... by @alice in https://..." or
# "... by @alice with @Copilot in https://...". Mentions in the title come before it.
AUTHORS = re.compile(r"^.* by (?P<authors>@.+?) in https://\S+$")
HANDLE = re.compile(r"@([A-Za-z0-9-]+(?:\[bot\])?)")
# AI coding assistants that GitHub lists as co-authors; not people to credit.
NON_HUMAN = {"copilot", "claude"}


def classify(entry):
    match = ENTRY.match(entry)
    if not match:
        return OTHER
    if match.group("bang"):
        return "Breaking changes"
    # Renovate titles runtime bumps "fix(deps)": group them as updates, not as fixes.
    if (match.group("scope") or "").lower().startswith("deps"):
        return "Dependency updates"
    commit_type = match.group("type").lower()
    for heading, types in SECTIONS:
        if commit_type in types:
            return heading
    return OTHER


def contributors(entries):
    # Keyed on the lowercased login, so "@Alice" and "@alice" count once.
    names = {}
    for entry in entries:
        match = AUTHORS.search(entry)
        if match:
            for name in HANDLE.findall(match.group("authors")):
                names.setdefault(name.lower(), name)
    humans = [
        name
        for key, name in names.items()
        if not key.endswith("[bot]") and key not in NON_HUMAN
    ]
    return sorted(humans, key=str.lower)


def group(notes):
    lines = notes.splitlines()
    try:
        start = lines.index(WHATS_CHANGED)
    except ValueError:
        return notes
    end = start + 1
    while end < len(lines) and not lines[end].startswith(("## ", "**Full Changelog**")):
        end += 1

    entries = [line for line in lines[start + 1 : end] if line.startswith("* ")]
    groups = {}
    for entry in entries:
        groups.setdefault(classify(entry), []).append(entry)

    out = [WHATS_CHANGED]
    for heading in [h for h, _ in SECTIONS] + [OTHER]:
        if heading in groups:
            out += ["", f"### {heading}", *groups[heading]]
    names = contributors(entries)
    if names:
        out += ["", "## Contributors", ", ".join(f"@{n}" for n in names)]
    out.append("")
    return "\n".join(lines[:start] + out + lines[end:]).rstrip("\n") + "\n"


if __name__ == "__main__":
    sys.stdout.write(group(sys.stdin.read()))
