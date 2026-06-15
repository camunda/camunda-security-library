---
status: Accepted
---

# ADR-0023: Hand-author spring-configuration-metadata.json for camunda.security.* properties

**Deciders**: @megglos, @joaquinfelici

## Status

Accepted

## Context

CSL's `spring-boot-starter` jar shipped no `META-INF/spring-configuration-metadata.json`.
Without it:

- IDEs offered no auto-completion or documentation for `camunda.security.*` properties.
- `PhysicalTenantOverridablePropertiesGoldenTest` in camunda/camunda (introduced in
  [camunda/camunda#54979](https://github.com/camunda/camunda/pull/54979)) reads every
  `spring-configuration-metadata.json` on the classpath to classify which `camunda.*` properties
  may be overridden per physical tenant. Without metadata, all `camunda.security.*` subtrees were
  either absent or reported as opaque group entries, making the deny-list in
  [camunda/camunda#55055](https://github.com/camunda/camunda/pull/55055) unverifiable.

The natural approach — adding `spring-boot-configuration-processor` to generate the file at
compile time — is blocked by two constraints:

1. **`@NestedConfigurationProperty` cannot be placed on fields in `api/`**: the annotation
   processor only recurses into a nested type when `@NestedConfigurationProperty` is present on
   the *field*. The top-level fields live in `CamundaSecurityLibraryProperties`
   (spring-boot-starter), which is fine. But the second-level fields live in config classes in the
   `api` module (e.g. `AuthenticationConfiguration.oidc`, `OidcConfiguration.assertion`). Adding
   `@NestedConfigurationProperty` there would require importing
   `org.springframework.boot.context.properties.NestedConfigurationProperty` into `api/`, which
   `ApiArchTest.API_MUST_NOT_DEPEND_ON_SPRING` explicitly forbids.

2. **The processor overwrites hand-authored files**: `maven-compiler-plugin` invokes the annotation
   processor after `resources:resources`. Any hand-authored
   `src/main/resources/META-INF/spring-configuration-metadata.json` would be overwritten by the
   processor's generated output, which would omit the deeper OIDC levels it cannot see.

The core question: how to ship a complete, accurate `spring-configuration-metadata.json` for
`camunda.security.*` properties without violating constraints.

## Decision

Ship a hand-authored `spring-configuration-metadata.json` in
`spring-boot-starter/src/main/resources/META-INF/spring-configuration-metadata.json` and guard it
with a reflection-based completeness test.

1. **Hand-authored metadata file** — `spring-boot-starter/src/main/resources/META-INF/spring-configuration-metadata.json`
   lists all `camunda.security.*` leaf properties and their enclosing groups. The file is written
   once and maintained alongside config class changes. No annotation processor is wired in.

2. **`SpringConfigurationMetadataCompletenessTest`** — a unit test in `spring-boot-starter` that:
   - Walks the config bean hierarchy starting from a fresh `CamundaSecurityLibraryProperties`
     instance using `java.beans.Introspector`. A class from `io.camunda.security.api.model.config.*`
     is treated as a group (recurse); any other writable property is a leaf.
   - Converts property names to kebab-case (matching Spring Boot's binding rules) and derives each
     leaf's type the way Spring Boot's processor would emit it: primitives boxed to their wrappers,
     generic signatures rendered without spaces.
   - Reads default values from the live bean graph and records which leaves have a non-null,
     non-empty runtime default (a fresh instance is substituted for any null nested bean).
   - Reads all `META-INF/spring-configuration-metadata.json` files on the test classpath.
   - Asserts, in both directions, that the file matches the reflection walk on three things: the
     leaf `properties` (name → type), the `groups` (name → type), and the set of properties that
     carry a `defaultValue`.

   This makes the metadata file self-enforcing: adding, removing, or retyping a property — or a
   change in whether it has a default — fails the test unless the file is updated, and a stale entry
   in the file without a corresponding bean property also fails. The rendered `defaultValue` string
   itself is not compared (see the accepted trade-offs).

### Why these particular boundaries

- **No annotation processor**: removing the processor means no build-time overwrite race and no
  need to add Spring dependencies to `api/`.
- **Reflection walk via `Introspector`**: uses only `java.beans` from the JDK — no extra
  dependencies. Skips read-only computed properties (e.g. `isApiProtected()`,
  `getCompiledIdValidationPattern()`) because they have no write method, which matches Spring
  Boot's binding behaviour.
- **Two-way assertion**: detecting only missing entries (or only extra entries) would allow
  silent drift in one direction. Both assertions are required.

## Consequences

**Positive**

- `camunda.security.*` properties appear in IDE auto-completion for any application that depends
  on `camunda-security-library-spring-boot-starter`.
- The `PhysicalTenantOverridablePropertiesGoldenTest` golden files in camunda/camunda can be
  regenerated with accurate leaf-level entries once the new CSL snapshot is published.
- No Spring dependency is introduced into `api/`; `ApiArchTest.API_MUST_NOT_DEPEND_ON_SPRING`
  continues to pass.
- Adding, removing, or retyping a config property — or changing whether it has a default — without
  updating the metadata file produces an immediate, clear test failure.

**Negative / accepted trade-offs**

- The metadata file must be updated manually whenever a config class changes (property added,
  removed, renamed, type changed). The completeness test catches omissions but does not generate
  the fix — a developer must edit the JSON by hand.
- The completeness test validates property names, types, group structure, and whether a
  `defaultValue` is present, but it does **not** validate the rendered `defaultValue` string, the
  `description` text, or the `sourceType`/`sourceMethod` fields. Those remain hand-maintained: a
  wrong default value, a stale description, or an incorrect source reference will not be caught and
  must be kept in sync by hand.

## Alternatives Considered

- **`spring-boot-configuration-processor` with `@NestedConfigurationProperty` on `api/` classes.**
  Rejected — would require importing `org.springframework.boot.context.properties.NestedConfigurationProperty`
  into `api/`, violating `ApiArchTest.API_MUST_NOT_DEPEND_ON_SPRING`. Even if the rule were relaxed,
  the processor cannot traverse types it sees only as compiled bytecode in a dependency jar unless
  `@NestedConfigurationProperty` annotations are present on every level of nesting.

- **Additional `spring-configuration-metadata.json` in the `api/` module itself.** Rejected —
  `api/` has no Maven dependency on `spring-boot`, so it has no BOM-managed processor version to
  reference. Shipping metadata from a module that contains no `@ConfigurationProperties` class also
  violates Spring Boot's processor conventions.

- **Shipping no metadata and relying on camunda/camunda's own processor run.** Rejected —
  camunda/camunda's processor sees `CamundaSecurityLibraryProperties` only as a compiled class in
  a jar dependency; it cannot traverse into it. The golden test would continue to report opaque
  subtrees rather than leaf-level properties.
