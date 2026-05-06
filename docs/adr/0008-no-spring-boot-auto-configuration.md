---
status: Accepted
supersedes: 0006-central-security-filter-chains.md (auto-configuration activation model only)
---

# ADR-0008: No Spring Boot auto-configuration — hosts explicitly import configurations

## Status

Accepted

## Context

[ADR-0006](0006-central-security-filter-chains.md) specified that the CSL's filter chains and
supporting beans would be shipped as Spring Boot auto-configurations, registered via
`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` and activated
by `@ConditionalOnProperty` gates.

The library is still under active development. Many configuration classes exist in
`spring-boot-starter/` as works-in-progress — they are incomplete, not yet integration-tested in
a host application, and not yet safe to be activated silently.

Spring Boot's auto-configuration mechanism activates every registered class on the classpath as
soon as a matching condition is satisfied, regardless of whether the host application has opted in
to that feature. This creates a real risk:

- A host application includes the CSL dependency.
- A partially implemented `@AutoConfiguration` class passes its `@ConditionalOnProperty` check
  because the host happens to set the required property (e.g., `camunda.security.authentication.method=oidc`).
- The unfinished configuration wires beans or security filter chains that conflict with or break
  the host's existing security setup.
- The host team has no visibility into what was activated — they did not write an `@Import` or
  register a bean; it just happened.

This failure mode is especially dangerous because the CSL manages security filter chains.
A silently-activated, broken chain can lock every user out of the host application, or worse,
silently weaken the security posture.

## Decision

**The CSL will not use Spring Boot auto-configuration while the library is under development.**

Concretely:

- There is no `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
  file in the starter module.
- Configuration classes in `spring-boot-starter/` are plain `@Configuration` classes (not
  `@AutoConfiguration`).
- Host applications explicitly import each configuration class they wish to activate, either via
  `@Import` in their own `@Configuration` class or by declaring the library's configuration class
  directly in their Spring context.
- A host imports a configuration only when it is ready to integrate that feature. Importing an
  unfinished or unsuitable configuration is a conscious, visible act — not a side-effect of
  adding the Maven dependency.

`@ConditionalOnMissingBean` is still used on library-supplied default beans so that a host which
imports a configuration class can still override individual beans without touching the
configuration class itself.

### What this means for adopters

Hosts include the `camunda-security-library-spring-boot-starter` dependency in their `pom.xml`
and then explicitly activate the configurations they need:

```java
@Configuration
@Import({
    BaseSecurityConfiguration.class,
    OidcApiSecurityConfiguration.class,
    OidcWebappSecurityConfiguration.class,
    OidcBeansConfiguration.class,
    AuthFailureHandlerConfiguration.class
})
public class MyHostSecurityConfiguration {}
```

Nothing activates unless the host opts in. If a CSL configuration class is not yet ready for a
given host, the host simply does not import it.

### Migration path

When the library reaches a stable, integration-tested state across Hub and OC, re-enabling
Spring Boot auto-configuration can be done by:

1. Registering the stable configuration classes in `AutoConfiguration.imports`.
2. Verifying each class with `ApplicationContextRunner` tests covering activation conditions,
   bean creation, and `@ConditionalOnMissingBean` back-off.
3. Writing a new ADR that supersedes this one.

This reversal does not require changing any configuration class — only the registration
mechanism changes.

## Consequences

**Positive**

- No unfinished or unsuitable configuration can activate silently in a host application.
- Hosts have full, explicit control over which library features are active. The decision is
  visible in the host's source code.
- Incremental integration is safe: a host can import one configuration at a time, verify it
  works, and add more as the library matures.
- Broken or incomplete configurations in the library cannot cause accidental outages in
  production hosts.

**Negative / accepted trade-offs**

- Hosts carry slightly more wiring code than in a pure auto-configuration story. This is
  intentional and temporary.
- There is no single "include the dep, set properties, done" story until the library is stable
  and auto-configuration is re-enabled. Adopter documentation must make the explicit import
  pattern clear.
- `@ConditionalOnProperty` gates on configuration classes have no effect while the classes are
  not auto-registered. They can remain in place for when auto-configuration is re-enabled, but
  hosts must not rely on them for activation control — the `@Import` list is the actual gate.

## Alternatives Considered

- **Keep auto-configuration, gate everything tightly with `@ConditionalOnProperty`.** Rejected —
  the root problem is that the library is not finished, not that the conditions are too permissive.
  Even perfectly gated conditions can be accidentally satisfied by a host property file.
  Explicit opt-in is safer than better-guarded implicit opt-in.

- **Keep auto-configuration but ship no classes registered in `AutoConfiguration.imports` yet.**
  Effectively equivalent to this ADR, but leaves an empty registration file that suggests the
  mechanism is in use — misleading for contributors. Not registering the file at all is clearer.

