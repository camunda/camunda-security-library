---
name: gradle-build-parity
description: Use when changing a pom.xml, a *.gradle.kts file, settings.gradle.kts, or anything under gradle/ (build-logic, wrapper), when the "Gradle build (parallel, advisory)" CI job fails, or when Maven and Gradle disagree about dependencies, versions, or checks. Maven is the source of truth; every build change must be mirrored in Gradle.
---

# Keep the Gradle build in parity with Maven

Follow the workflow in `docs/workflows/gradle-build-parity.md`.

Read that file and follow it exactly. It covers the rules (Maven is the source of truth, no versions in Gradle files, both builds change together), where each concern lives in both builds, the scope and plugin mappings, how to port a POM change, and the commands that verify parity.
