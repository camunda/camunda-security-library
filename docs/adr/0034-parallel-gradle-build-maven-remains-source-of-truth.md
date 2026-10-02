---
status: Proposed
---

# ADR-0034: Add a parallel Gradle build; Maven remains the source of truth and publishes

**Deciders**: Patrick Wunderlich, Nicolas Pepin-Perreault

## Status

Proposed

## Context

CSL builds with Maven. [#698](https://github.com/camunda/camunda-security-library/issues/698) wants
to move it to Gradle for faster local and CI builds through incremental compilation, the build cache,
and the configuration cache. The Camunda monorepo is trying the same thing. Its proposed ADR
[camunda/camunda#63133](https://github.com/camunda/camunda/pull/63133)
(`docs/adr/gradle/001-gradle-experimental-ci-integration.md`) runs Gradle next to Maven under these
rules:

- D1: Maven is the source of truth.
- D2: Gradle defines no independent library versions.
- D3: Maven and Gradle changes are kept in sync.
- Gradle does not publish external artifacts.

Replacing Maven needs a further decision, which that ADR leaves to a future record.
[camunda/camunda#52869](https://github.com/camunda/camunda/pull/52869) already contains build logic
that reads POM properties into a Gradle version catalog, safely for the configuration cache.

CSL publishes and releases entirely through Maven:

- The parent `org.camunda:camunda-release-parent` supplies the Nexus repositories, GPG signing, the
  sources and javadoc jars, and the `central-sonatype-publish` profile. The root `pom.xml` overrides
  that profile to set `autoPublish=true` and `waitUntil=published`.
- `release.yml` runs `release:prepare` and `release:perform`. It waits up to 3600 s for the Maven
  Central deployment.

Replacing that path means choosing a Maven Central publishing plugin, a release mechanism, the
published artifact layout, and a rule for maintenance branches. The 8.10 patch releases depend on
this path staying untouched. No numbers yet show what Gradle saves for CSL (#702).

How does CSL get a Gradle build without changing what it ships or how it releases?

## Decision

CSL adds a Gradle build next to Maven and adopts the monorepo's rules unchanged: D1–D3, and Gradle
publishes nothing.

- **Maven stays authoritative.** Maven builds, tests, and publishes every artifact consumers resolve.
  `release.yml`, the `central-sonatype-publish` profile, and `camunda-release-parent` stay unchanged.
  The Gradle build runs as an extra CI job on every PR. It starts as advisory, not a required check,
  and becomes a required PR check once it runs reliably. It never gates releases.
- **Versions come from the POM.** CSL forks `PomResolver` and `SettingsPomResolverPlugin` (plugin id
  `io.camunda.gradle.settings-pom-resolver`) from camunda/camunda#52869 into an included build,
  `gradle/build-logic`. A header comment records the source commit SHA. `settings.gradle.kts` builds
  the `libs` catalog in code from the root `pom.xml` `<properties>`, resolving each key on its own.
  The POM is read through `providers.fileContents`, so it is a configuration-cache input. No library
  version appears in a Gradle file.
- **Gradle mirrors Maven's checks.** The checks are compilation, tests, Spotless with the license
  header, Checkstyle, Javadoc, dependency convergence, and dependency analysis. A CI script compares
  each module's Maven and Gradle classpaths (#700).
- **Cutover is deferred.** A follow-up ADR decides whether and when Gradle becomes the source of
  truth and Maven is removed. It should rest on the build-time comparison in #702, and it must pick:
  - the Maven Central publishing plugin;
  - the replacement for `maven-release-plugin` and where the project version lives;
  - the published artifact changes;
  - how pre-cutover maintenance branches are released;
  - what replaces `camunda-release-parent`;
  - where the git hooks live once `.mvn/` is removed.
- **Merge hold.** Nothing under #698 merges before the Camunda 8.10 release (13 Oct 2026).

### Why these particular boundaries

- **Same rules as the monorepo.** CSL adds no build policy of its own. When the monorepo decides its
  cutover, CSL can follow or diverge on purpose.
- **Publishing stays on the tested path.** Release automation keeps its current behaviour through the
  8.10 maintenance window.
- **Fork, not dependency.** camunda/camunda#52869 is unmerged and is not published as a plugin, so a
  copy is the only option today. CSL takes only the POM resolver. It skips the monorepo's
  `catalog/*Libraries.kt` / `CatalogVersions.kt` split, because the root POM pins only a handful of
  library versions (Spring Boot, ArchUnit, Testcontainers, nimbus-jose-jwt, commons-validator), plus
  tool versions. The BOMs supply the rest, so the catalog fits inline in `settings.gradle.kts`.

## Consequences

**Positive**

- Consumers see no change: Maven still produces the artifacts, coordinates, and dependencies Hub, OC,
  and Optimize resolve.
- Release automation is untouched.
- Gradle's build time and cache behaviour can be measured on the real codebase before anything depends
  on it.
- The version resolver and the Maven/Gradle classpath comparison script (#700) exist only for the
  parallel phase. A cutover removes them together with the POMs.

**Negative / accepted trade-offs**

- Two builds must be maintained, with no end date. Every build change is made twice (D3), and a POM
  edit can break Gradle.
- A green Gradle build does not verify the shipped artifact, because Maven builds what is published.
- The version resolver is a fork of unmerged code and does not get upstream fixes on its own.
- Changes to `camunda-release-parent` keep reaching only the Maven build.
- While the Gradle job is advisory, D3 relies on review: a PR that breaks Gradle can still merge.
- The git hooks stay in `.mvn/hooks/`, and only a Maven build sets `core.hooksPath` (during
  `initialize`). A Gradle-only contributor gets no hooks until they run Maven once or set
  `core.hooksPath` themselves.

## Alternatives Considered

- **Switch fully now, with Gradle publishing and Maven removed.** Rejected for now: it needs a
  publishing plugin, a release mechanism, and artifact changes chosen before #702 shows whether Gradle
  pays off, and it puts the 8.10 patch releases on an untested release path. The follow-up ADR
  revisits it.
- **A separate `gradle/libs.versions.toml` during the parallel phase.** Viable if the parallel window
  is short. Rejected: it contradicts D2, and with no fixed end to the parallel phase, two version
  sources would drift. The toml becomes the version source only at cutover.
- **No Gradle build.** Rejected: without it, #698 has nothing to measure.
