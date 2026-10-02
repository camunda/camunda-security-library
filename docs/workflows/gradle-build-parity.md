# Gradle Build Parity

This workflow keeps the parallel Gradle build in step with Maven. Maven stays the source of truth
and is the only build that publishes ([ADR-0034](../adr/0034-parallel-gradle-build-maven-remains-source-of-truth.md)).

It applies whenever you change a `pom.xml`, a `*.gradle.kts` file, or anything under `gradle/`, or
when the advisory `Gradle build (parallel, advisory)` CI job fails. It is adapted from the Camunda
monorepo's `gradle-build-parity` skill ([camunda/camunda#52869](https://github.com/camunda/camunda/pull/52869)),
trimmed to what CSL has.

Claude Code users: this workflow is also available as `/gradle-build-parity`.

## Rules

These are the monorepo's rules, which ADR-0034 adopts unchanged:

- **D1 — Maven is the source of truth.** If the builds disagree, Gradle is wrong.
- **D2 — Gradle defines no versions of its own.** Every library and tool version is read from the
  root `pom.xml` `<properties>` in `settings.gradle.kts` (`pomVersion("…")`). Never write a version
  literal in a Gradle file. The only exception is Gradle plugin versions, which have no Maven
  equivalent (for example the dependency-analysis plugin in the root `build.gradle.kts`).
- **D3 — Maven and Gradle change together.** A PR that changes one build changes the other.

## Where things live

| Concern | Maven | Gradle |
|---|---|---|
| Versions | root `pom.xml` `<properties>` and `<dependencyManagement>` | read in `settings.gradle.kts` into the `libs` catalog |
| Modules | `<modules>` in the root `pom.xml` | `registerProject(…)` in `settings.gradle.kts`; project name = Maven `artifactId` |
| Dependencies | `<module>/pom.xml` | `<module>/build.gradle.kts` |
| Shared build config | root `pom.xml` `<build>` | `gradle/build-logic/src/main/kotlin/csl.java-conventions.gradle.kts` |
| Version resolution | — | `gradle/build-logic/pom-resolution` (`PomResolver`, forked from the monorepo) |

## Scope mapping

| Maven scope | Gradle configuration |
|---|---|
| `compile`, type appears in the module's public API | `api` |
| `compile`, used only internally | `implementation` |
| `provided` | `compileOnly` |
| `runtime` | `runtimeOnly` |
| `test` | `testImplementation`; engines and other runtime-only test deps use `testRuntimeOnly` |

`api` versus `implementation` is enforced by the dependency-analysis plugin. Follow its advice
rather than guessing.

## Plugin equivalents

| Maven | Gradle (in `csl.java-conventions` unless noted) |
|---|---|
| `maven-compiler-plugin` `release` | `options.release` from `maven.compiler.release` |
| `maven-surefire-plugin` | `useJUnitPlatform()` plus an explicit `junit-platform-launcher` |
| `maven-jar-plugin` manifest entries | `tasks.jar` manifest |
| `<dependencyManagement>` BOM imports and pins | `enforcedPlatform(…)` BOMs and `strictly` constraints |
| `maven-enforcer-plugin` `dependencyConvergence` | `failOnVersionConflict()` |
| `maven-dependency-plugin` `analyze-only` | dependency-analysis plugin (root `build.gradle.kts`), `projectHealth` gates `check` |
| `spotless-maven-plugin` | Spotless with google-java-format and `COPYING-HEADER.txt` |
| `maven-checkstyle-plugin` | `checkstyle` with `config/checkstyle/checkstyle.xml` |
| `maven-javadoc-plugin` `verify-javadoc` | `tasks.javadoc` with doclint, wired into `check` |

Release and publishing plugins (`maven-release-plugin`, `central-publishing-maven-plugin`, the
`camunda-release-parent` setup) have no Gradle equivalent on purpose. Gradle publishes nothing.

## Porting a POM change

| You changed in Maven | Change in Gradle |
|---|---|
| A version property | Nothing, if the catalog already reads it. If it is new, add `version(…, pomVersion("…"))` and the matching `library(…)` in `settings.gradle.kts`. |
| A version pinned in `<dependencyManagement>` | Add the property to the catalog and the artifact to the `strictly` constraint list in `csl.java-conventions`. |
| A new dependency managed by a BOM | Add `library(…).withoutVersion()` to the catalog, then the dependency to the module's `build.gradle.kts` with the mapped configuration. |
| A removed dependency | Remove it from `build.gradle.kts`, and from the catalog if nothing else uses it. |
| A new module | `registerProject(…)` in `settings.gradle.kts`, plus a `build.gradle.kts` applying `csl.java-conventions` and the dependency-analysis plugin. |
| A new or reconfigured build plugin | The equivalent in `csl.java-conventions`, or a note in the PR explaining why it is Maven-only. |
| An exclusion | The matching `exclude(…)`. Check the result with the comparison script, because Maven and Gradle apply exclusions differently. |

The reverse also holds: a dependency added only in Gradle is a D3 violation.

## Verify

Run all of these before declaring parity work complete:

```sh
./gradlew build                                   # compile, test, Spotless, Checkstyle, Javadoc, dependency analysis
./gradlew -p gradle/build-logic check             # tests for the build logic (not run by the root build)
python3 .github/scripts/compare-module-deps.py    # Maven vs Gradle classpaths, every module and scope
```

`compare-module-deps.py` accepts a module and `--scope` to narrow a failing run. Its allowlists
(`ALLOWED_GRADLE_EXTRA`, `ALLOWED_GRADLE_MISSING`) are for differences inherent to the two tools.
Don't add an entry to hide a declaration mistake. Each entry states its reason.

The CI job also runs `./gradlew build` a second time and fails if any task re-executes. If that
fails, the listed task has undeclared or unstable inputs or outputs; fix the task rather than the
check. Only `projectHealth`, which declares no outputs, is tolerated.
