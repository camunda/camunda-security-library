---
status: Accepted
---

# ADR-0035: Declare nullness with JSpecify and check it with NullAway

**Deciders**: Lukas Taake

## Status

Accepted

## Context

CSL has no machine-readable nullness contract. Whether a parameter, return value or record component can be `null` is only visible in the code or in Javadoc, and nothing checks it. Hosts that embed CSL (Hub, Orchestration Clusters) and their tools (IDEs, Kotlin) cannot tell either.

Spring Framework 7, and so Spring Boot 4, uses [JSpecify](https://jspecify.dev) annotations for its own API. The Spring Boot BOM that CSL imports manages the `org.jspecify:jspecify` version.

How does CSL declare and check nullness without a big-bang change to the code?

## Decision

- **JSpecify declares nullness.** `org.jspecify:jspecify` is a compile-scope dependency of `api`, `core`, `validation` and `spring-boot-starter`. Its version comes from the Spring Boot BOM. The annotations are not Spring, Jackson or zeebe types, so `core` stays within `DomainArchTest`.
- **Every production package is `@NullMarked`.** Each package under `src/main/java` has a `package-info.java` with `@NullMarked`. Types, parameters, return values and fields are non-null unless a `@Nullable` says otherwise. `NullMarkedArchTest` in `core`, `validation` and `spring-boot-starter` (`core` also covers `api`) fails the build when a package has none.
- **NullAway checks production code.** NullAway runs as an Error Prone plugin in the `default-compile` execution of `maven-compiler-plugin`. It runs with `-XepDisableAllChecks -Xep:NullAway:WARN -XepOpt:NullAway:OnlyNullMarked=true`. Test code is not checked.
- **The rollout has two steps.** This ADR's change surfaces the violations as warnings and does not fail the build. A follow-up change fixes them and raises NullAway to `ERROR`. A new ADR is not needed for that step, but this ADR's text for the severity must then be read as superseded by the follow-up PR.
- **The Error Prone flags go in `.mvn/jvm.config`.** The compiler runs inside the Maven JVM, and Error Prone needs `--add-exports`/`--add-opens` flags on JDK 16+.

### Why these particular boundaries

- **A `package-info.java` per package, not one per module.** `@NullMarked` applies to one package and does not cascade to subpackages. A single annotation on `io.camunda.security.api` would mark almost none of the code. The ArchUnit test closes the gap for new packages.
- **`OnlyNullMarked` instead of `AnnotatedPackages`.** NullAway then checks exactly the code that declares the contract, and tools that read the annotations see the same boundary as NullAway.
- **`-XepDisableAllChecks`.** Error Prone's default checks include `ERROR`-level ones. Without the flag, the step could fail the build, and every other check would add warnings.
- **Production code only.** `@InjectMocks` fields and similar test idioms are `null` by design and would bury the production warnings.
- **`.mvn/jvm.config` instead of forked compilation.** `mvnw` and the pre-push hook read it, and it keeps the compiler in-process. Forking would need `-J` flags in the POM and slows the build.
- **No `JSpecifyMode`.** The generics-aware checks add many warnings. They can be a later step once the plain checks are at `ERROR`.

## Consequences

**Positive**

- Nullness is visible to IDEs, Kotlin consumers and Spring, and checked at build time.
- New code is non-null by default, and the build shows where it is not.
- The warn-only step does not change the build outcome.

**Negative / accepted trade-offs**

- The build log shows NullAway warnings until the follow-up change lands.
- Compilation is slower, and Error Prone and NullAway are a new build dependency that must support the JDK in use.
- The JVM flags in `.mvn/jvm.config` apply to the whole Maven run. An IDE or CI job that does not read the file cannot run the Error Prone compile.
- A new package without a `package-info.java` fails the build through the ArchUnit test.

## Alternatives Considered

- **Checker Framework.** Rejected. It is slower and needs more annotations than NullAway for the same result.
- **`@NullMarked` on the top-level package of each module only.** Rejected. It does not cascade to subpackages.
- **`AnnotatedPackages` without `package-info.java` files.** Rejected. Only NullAway sees the contract.
- **`ERROR` severity from the start.** Rejected. It needs all violations fixed in one change, which is not a small, reviewable PR.
- **Spring's `@Nullable`/`@NonNullApi`.** Rejected. They are Spring types, and `core` must stay framework-free.
