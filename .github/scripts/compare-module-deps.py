#!/usr/bin/env python3
"""Compare each module's resolved third-party classpath between Maven and Gradle.

Adapted from camunda/camunda#52869 (commit 42422bbb6675899f46d494414fc17cfd8177abb0),
`.claude/skills/gradle-build-parity/compare-module-deps.py`.

Maven is the source of truth (ADR-0034); the parallel Gradle build must resolve the same
dependencies. For every Maven reactor module and each scope this script resolves the classpath
with both tools and diffs it:

  * third-party deps by `group:artifact` (missing / extra), and their resolved versions
    (exact equality; any difference is reported),
  * internal deps (reactor modules vs Gradle projects) by name. Gradle project names equal the
    Maven artifactIds, so a mismatch there is a real difference.

Scope mapping (Maven dependency:list includeScope -> Gradle configuration):
  compile -> compileClasspath      (Maven compile also includes provided; Gradle includes compileOnly)
  runtime -> runtimeClasspath
  test    -> testRuntimeClasspath  (Maven test = everything)

A dependency Maven has on a module's compile classpath only transitively, and Gradle keeps on its
runtime classpath because a sibling declares it `implementation`, is reported but not a failure.

Gradle imported BOMs/platforms are not counted (Maven does not list imported BOMs either).

Usage:
  python3 .github/scripts/compare-module-deps.py                    # all modules, all scopes
  python3 .github/scripts/compare-module-deps.py core               # one module (dir or artifactId)
  python3 .github/scripts/compare-module-deps.py --scope test --json

Exit code: 0 = identical, 1 = differences or errors.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

REPO_ROOT = Path(__file__).resolve().parents[2]
INIT_SCRIPT = ".github/scripts/gradle-resolved-deps.init.gradle"
POM_NS = "{http://maven.apache.org/POM/4.0.0}"

# Maven scope -> Gradle configuration.
SCOPES = {
    "compile": "compileClasspath",
    "runtime": "runtimeClasspath",
    "test": "testRuntimeClasspath",
}

# Differences inherent to the tools (not Gradle declaration mistakes), per coordinate and scope.
# Keep this list small and justified; everything else is reported as a failure.
ALLOWED_GRADLE_EXTRA: dict[str, tuple[set[str], str]] = {
    "org.junit.platform:junit-platform-launcher": (
        {"test"},
        "Gradle's test runtime needs the launcher declared explicitly; Maven Surefire brings its own",
    ),
    "ch.qos.logback:logback-classic": (
        {"compile", "runtime"},
        "starter module declares logback at test scope; Maven scope mediation demotes the "
        "transitive compile path (spring-boot-starter-logging) to test, Gradle keeps both",
    ),
    "ch.qos.logback:logback-core": (
        {"compile", "runtime"},
        "same as logback-classic",
    ),
}
ALLOWED_GRADLE_MISSING: dict[str, tuple[set[str], str]] = {
    "org.apiguardian:apiguardian-api": (
        {"test"},
        "compile dependency in the JUnit POMs, dropped from the JUnit Gradle module metadata",
    ),
    "org.jspecify:jspecify": (
        {"test"},
        "compile dependency in the JUnit POMs, dropped from the JUnit Gradle module metadata",
    ),
}


def allowed(table: dict[str, tuple[set[str], str]], scope: str, coordinate: str) -> bool:
    return coordinate in table and scope in table[coordinate][0]


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stdout}\n{result.stderr}"
        )
    return result.stdout


def reactor_modules() -> dict[str, str]:
    """Return {artifactId: directory} for the modules listed in the root POM."""
    root = ElementTree.parse(REPO_ROOT / "pom.xml").getroot()
    modules = {}
    for module in root.findall(f"{POM_NS}modules/{POM_NS}module"):
        directory = (module.text or "").strip()
        pom = ElementTree.parse(REPO_ROOT / directory / "pom.xml").getroot()
        modules[pom.findtext(f"{POM_NS}artifactId")] = directory
    return modules


def maven_deps(modules: dict[str, str], scope: str) -> dict[str, dict]:
    """Resolve all modules in one reactor build; dependency:list writes one file per module.

    `compile` runs first so reactor siblings resolve to target/classes without packaging.
    """
    output_file = f"target/csl-deps-{scope}.txt"
    run([
        "./mvnw", "-B", "-q", "-Dskip.hooks=true", "compile", "dependency:list",
        f"-DincludeScope={scope}", f"-DoutputFile={output_file}",
    ])
    reports = {}
    for artifact, directory in modules.items():
        third_party: dict[str, str] = {}
        internal: set[str] = set()
        for line in (REPO_ROOT / directory / output_file).read_text().splitlines():
            # "group:artifact:type[:classifier]:version:scope[ -- module ...]"
            parts = line.strip().split(" ")[0].split(":")
            if len(parts) < 5:
                continue
            group, name, version = parts[0], parts[1], parts[-2]
            if name in modules:
                internal.add(name)
            else:
                third_party[f"{group}:{name}"] = version
        reports[artifact] = {"third_party": third_party, "internal": internal}
    return reports


def gradle_deps() -> dict[tuple[str, str], dict]:
    """Return {(project, configuration): report} for all Gradle projects in one build."""
    out = run([
        "./gradlew", "-q", "--console=plain", "--no-configuration-cache",
        "-I", INIT_SCRIPT, "cslResolvedDeps",
    ])
    reports = {}
    for line in out.splitlines():
        if line.startswith("{"):
            entry = json.loads(line)
            reports[(entry["project"], entry["configuration"])] = {
                "third_party": entry["third_party"],
                "internal": set(entry["internal"]),
            }
    return reports


def compare(scope: str, maven: dict, gradle: dict, gradle_runtime: dict) -> dict:
    missing = set(maven["third_party"]) - set(gradle["third_party"])
    # Maven puts every transitive compile dependency on a consumer's compile classpath; Gradle's
    # `implementation` keeps it on the runtime classpath only. That is the intended api/implementation
    # split, so a compile-scope gap is accepted when Gradle still resolves the dependency at runtime.
    narrowed = (
        sorted(c for c in missing if c in gradle_runtime["third_party"]) if scope == "compile" else []
    )
    third_party_missing = sorted(
        c for c in missing - set(narrowed) if not allowed(ALLOWED_GRADLE_MISSING, scope, c)
    )
    third_party_extra = sorted(
        c for c in set(gradle["third_party"]) - set(maven["third_party"])
        if not allowed(ALLOWED_GRADLE_EXTRA, scope, c)
    )
    versions = [
        {"coordinate": c, "maven": maven["third_party"][c], "gradle": gradle["third_party"][c]}
        for c in sorted(set(maven["third_party"]) & set(gradle["third_party"]))
        if maven["third_party"][c] != gradle["third_party"][c]
    ]
    return {
        "missing_in_gradle": third_party_missing,
        "implementation_only": narrowed,
        "extra_in_gradle": third_party_extra,
        "version_mismatches": versions,
        "internal_missing_in_gradle": sorted(maven["internal"] - gradle["internal"]),
        "internal_extra_in_gradle": sorted(gradle["internal"] - maven["internal"]),
        "counts": {"maven": len(maven["third_party"]), "gradle": len(gradle["third_party"])},
    }


def format_result(project: str, scope: str, diff: dict) -> tuple[bool, str]:
    lines = []
    for key, label in (
        ("missing_in_gradle", "MISSING in Gradle"),
        ("extra_in_gradle", "EXTRA in Gradle"),
        ("internal_missing_in_gradle", "MISSING internal project in Gradle"),
        ("internal_extra_in_gradle", "EXTRA internal project in Gradle"),
    ):
        lines += [f"    {label}: {c}" for c in diff[key]]
    lines += [
        f"    VERSION {v['coordinate']}: maven={v['maven']} gradle={v['gradle']}"
        for v in diff["version_mismatches"]
    ]
    counts = diff["counts"]
    status = "DIFF" if lines else "ok  "
    header = f"  [{status}] {project} / {scope} (third-party maven={counts['maven']} gradle={counts['gradle']})"
    notes = [f"    runtime-only in Gradle (implementation): {c}" for c in diff["implementation_only"]]
    return not lines, "\n".join([header, *lines, *notes])


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare Maven and Gradle resolved classpaths.")
    parser.add_argument("module", nargs="?", help="limit to one module (directory or artifactId)")
    parser.add_argument("--scope", choices=SCOPES, help="limit to one scope (default: all)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args()

    modules = reactor_modules()
    if args.module:
        by_dir = {d: a for a, d in modules.items()}
        selected = by_dir.get(args.module, args.module)
        if selected not in modules:
            print(f"unknown module {args.module!r}; known: {sorted(modules)}", file=sys.stderr)
            return 1
        targets = [selected]
    else:
        targets = sorted(modules)
    scopes = [args.scope] if args.scope else list(SCOPES)

    try:
        gradle = gradle_deps()
        results = []
        for scope in scopes:
            maven = maven_deps(modules, scope)
            for project in targets:
                if (project, SCOPES[scope]) not in gradle:
                    raise RuntimeError(f"Gradle reported nothing for {project}/{SCOPES[scope]}")
                diff = compare(
                    scope,
                    maven[project],
                    gradle[(project, SCOPES[scope])],
                    gradle[(project, SCOPES["runtime"])],
                )
                results.append((project, scope, diff))
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps([{"project": p, "scope": s, **d} for p, s, d in results], indent=2))
        return 0 if all(format_result(p, s, d)[0] for p, s, d in results) else 1

    all_ok = True
    for project, scope, diff in results:
        ok, text = format_result(project, scope, diff)
        all_ok &= ok
        print(text)
    print("\nOK: Maven and Gradle classpaths match." if all_ok else "\nFAIL: differences found.")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
