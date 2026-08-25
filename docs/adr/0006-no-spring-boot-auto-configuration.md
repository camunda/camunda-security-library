---
status: Accepted
---

# ADR-0006: Security configuration: chain catalog and explicit host activation

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

The CSL is embedded into multiple host applications (Hub, Orchestration Cluster gateways) that
historically maintained their own Spring Security configurations. This duplicated
API/webapp `securityMatcher` wiring, OIDC and Basic-auth filter chain plumbing, CSRF protection
logic, hardened HTTP response headers, and OAuth2 refresh-token handling per host. Inconsistencies
between host configurations repeatedly produced security regressions — different CSP defaults,
missing CSRF, divergent failure-handler behaviour, drift between OIDC API and webapp chains.
Centralising this logic in the CSL is a prerequisite for the "always-on AuthN/AuthZ enforcement"
guarantee in [ADR-0002](0002-placement-of-the-security-gateway-framework.md). It also means every
host needs the same runtime beans (`JwtDecoder`, `ClientRegistrationRepository`, OAuth2 client
beans) built from the same property surface — asking each adopter to construct them by hand would
multiply the same code across every consumer for no benefit.

The library ships this centralised logic as a `camunda-security-library-spring-boot-starter`
artefact. The open question is *how a host activates it*. While the library is still under active
development, many configuration classes in `spring-boot-starter/` are works in progress —
incomplete, not yet integration-tested in a host application, and not safe to activate silently.
Spring Boot's auto-configuration mechanism activates every registered class on the classpath as
soon as a matching condition is satisfied, regardless of whether the host has actually opted in to
that feature:

- A host application includes the CSL dependency.
- A partially implemented auto-configuration class passes its condition because the host happens
  to set a matching property (e.g. `camunda.security.authentication.method=oidc`).
- The unfinished configuration wires beans or filter chains that conflict with, or break, the
  host's existing security setup.
- The host team has no visibility into what activated — they did not write an `@Import` or
  register a bean; it just happened.

This failure mode is especially dangerous because the CSL manages security filter chains: a
silently activated, broken chain can lock every user out of the host application, or worse,
silently weaken the security posture.

What set of configuration classes and default beans does the CSL ship, and how does a host make
them active without risking silent, unreviewed activation?

## Decision

**The CSL ships the filter chains and supporting beans as plain `@Configuration` classes; hosts
activate them by explicit opt-in, not by Spring Boot auto-configuration, while the library is
under development.**

### The chain catalog

| Class | Purpose |
|---|---|
| `BaseSecurityConfiguration` | Always relevant — unprotected-paths chain and catch-all deny chain |
| `OidcApiSecurityConfiguration` | API chain for OIDC-authenticated hosts |
| `OidcWebappSecurityConfiguration` | Webapp chain for OIDC-authenticated hosts |
| `BasicAuthApiSecurityConfiguration` | API chain for Basic-auth hosts |
| `BasicAuthWebappSecurityConfiguration` | Webapp chain for Basic-auth hosts |
| `UnprotectedApiSecurityConfiguration` | Development-only permit-all API chain; logs a startup warning |

Plus `OidcBeansConfiguration` (OIDC default beans, gated on `method=oidc`) and
`AuthFailureHandlerConfiguration` (unconditional at the class level — only its bean carries
`@ConditionalOnMissingBean`). Five of the six chain classes above —
`OidcApiSecurityConfiguration`, `OidcWebappSecurityConfiguration`,
`BasicAuthApiSecurityConfiguration`, `BasicAuthWebappSecurityConfiguration`, and
`UnprotectedApiSecurityConfiguration` — each carry a `@ConditionalOnProperty` or an equivalent
small `@Conditional` class matching the auth-method/unprotected-API matrix their names imply.
`BaseSecurityConfiguration` is, like `AuthFailureHandlerConfiguration`, unconditional at the class
level (plain `@Configuration @EnableWebSecurity`) — its unprotected-paths chain bean is always
registered when the class is imported; a separate `@Bean`-level `@ConditionalOnProperty` on its
catch-all-deny-chain bean gates that one bean on
`camunda.security.authentication.catch-all-unhandled-paths-enabled`, an unrelated, narrower
concern than the auth-method matrix. None of these conditions are what activates a class today —
see *Activation model* below — they exist so the classes are ready to be auto-registered once the
library re-enables auto-configuration (see *Migration path*).

The library also supplies default beans for `JwtDecoder`, `ClientRegistrationRepository`,
`OAuth2AuthorizedClientRepository`, `OAuth2AuthorizedClientManager`, and a default
`AuthFailureHandler` (`JsonProblemDetailAuthFailureHandler`). Each is annotated
`@ConditionalOnMissingBean` on every activation path; whether a host override reliably displaces
the default in practice depends on the path taken — see *Optional opt-in umbrella
`@AutoConfiguration`* below.

The host-facing contract is `SecurityPathPort` (in `core`) plus the OAuth2 extension hooks
`OidcTokenEndpointCustomizer` and `OidcResourceServerCustomizer`. Hosts register beans of those
types; the library consumes them via `ObjectProvider`.

Configuration is bound through `CamundaSecurityLibraryProperties`
(`@ConfigurationProperties(prefix = "camunda.security")`), covering authentication, authorization,
CSRF, headers, session, multi-tenancy, and related property groups.

### Activation model

- There is no `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
  file in the starter module.
- Configuration classes in `spring-boot-starter/` are plain `@Configuration` classes, not
  `@AutoConfiguration`.
- Host applications explicitly import each configuration class they wish to activate, either via
  `@Import` in their own `@Configuration` class or by declaring the library's configuration class
  directly in their Spring context.
- A host imports a configuration only when it is ready to integrate that feature. Importing an
  unfinished or unsuitable configuration is a conscious, visible act — not a side-effect of adding
  the Maven dependency.

`@ConditionalOnMissingBean` is still evaluated on library-supplied default beans so a host that
imports a configuration class can override individual beans without touching the configuration
class itself.

### Optional opt-in umbrella `@AutoConfiguration`

The CSL ships a single optional umbrella class —
`io.camunda.security.spring.CamundaSecurityAutoConfiguration` — that `@Import`s every CSL
configuration class. The umbrella is annotated `@AutoConfiguration` but is **not** registered in
CSL's `AutoConfiguration.imports`, so the rule above still holds: adding the Maven dependency alone
activates nothing.

Hosts that want the full CSL stack with a single opt-in can activate the umbrella by either:

- annotating one of their own configuration classes with
  `@ImportAutoConfiguration(CamundaSecurityAutoConfiguration.class)`, or
- listing it in their own
  `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` file.

When the host opts in this way, Spring loads the umbrella in the deferred auto-configuration
phase — after every host `@Configuration` class has been parsed. The CSL's `@ConditionalOnBean`
and `@ConditionalOnMissingBean` gates then evaluate against the full bean graph and behave as
documented, so host-supplied SPIs are visible and host overrides correctly displace the library
defaults.

Hosts that prefer fine-grained control can still `@Import` individual CSL configuration classes
directly. In that path Spring evaluates the conditional gates against a partial bean graph (the
condition evaluator runs as each user `@Configuration` is parsed, and the host's own
`@Configuration` siblings may not be parsed yet). Adopters following the fine-grained path
therefore accept the conditional-bean fragility and work around it where needed — for example by
eagerly registering the host SPIs that CSL configurations depend on.

### What this means for adopters

Hosts include the `camunda-security-library-spring-boot-starter` dependency in their `pom.xml` and
explicitly opt in. Two paths:

1. **Umbrella (single opt-in for the full CSL stack):**

   ```java
   @ImportAutoConfiguration(CamundaSecurityAutoConfiguration.class)
   public class HubSecurityConfiguration {}
   ```

   Or, equivalently, list `io.camunda.security.spring.CamundaSecurityAutoConfiguration` in the
   host's own `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.

2. **Fine-grained `@Import`** when activating only part of CSL or while individual configurations
   are still being adopted:

   ```java
   @Configuration
   @Import({
       BaseSecurityConfiguration.class,
       OidcApiSecurityConfiguration.class,
       OidcWebappSecurityConfiguration.class,
       OidcBeansConfiguration.class,
       AuthFailureHandlerConfiguration.class
   })
   public class HubSecurityConfiguration {}
   ```

Nothing activates unless the host opts in via one of these two paths. If a CSL configuration is
not yet ready for a given host, the host simply omits it from the `@Import` list (path 2) or
defers adopting the umbrella (path 1).

### Migration path

When the library reaches a stable, integration-tested state across Hub and OC, re-enabling Spring
Boot auto-configuration can be done by:

1. Registering the stable configuration classes in `AutoConfiguration.imports`.
2. Verifying each class with `ApplicationContextRunner` tests covering activation conditions, bean
   creation, and `@ConditionalOnMissingBean` back-off.
3. Writing a new ADR that supersedes this one.

This does not require changing any configuration class — only the registration mechanism changes.

### Deferred: deployment-strategy activation

A `Strategy` enum (`oc-standalone`/`oc-managed`/`hub`) and a `camunda.security.strategy` property
were proposed alongside the original chain catalog, to let the active deployment strategy drive
which policy-authority behaviour is active. That remains deferred and unresolved: no `Strategy`
enum, `camunda.security.strategy` property, or `DeploymentStrategy` type exists in the codebase
today. Deployment strategy is a policy-authority concern, not an authentication concern, and
belongs to the policy work tracked separately; the filter-chain activation model described in this
ADR does not depend on it.

## Consequences

**Positive**

- No unfinished or unsuitable configuration can activate silently in a host application.
- Hosts have full, explicit control over which library features are active. The decision is
  visible in the host's source code.
- Incremental integration is safe: a host can import one configuration at a time, verify it works,
  and add more as the library matures.
- Broken or incomplete configurations in the library cannot cause accidental outages in production
  hosts.
- CSRF, secure headers, refresh-token, and failure-handler behaviour are uniform across every host
  that adopts the chains, regardless of activation path — host configurations can no longer drift
  on these baselines.
- Library defaults reduce per-host duplication: `JwtDecoder` is built from
  `camunda.security.authentication.oidc.*` properties, likewise `ClientRegistrationRepository` and
  the OAuth2 client beans. A host that needs a different shape (multi-IdP, custom token validator,
  `private_key_jwt`) registers its own bean and the library's default backs off.

**Negative / accepted trade-offs**

- Hosts carry slightly more wiring code than in a pure auto-configuration story. This is
  intentional and temporary.
- There is no single "include the dep, set properties, done" story until the library is stable and
  auto-configuration is re-enabled. The adopter guide (`docs/adopters/security-filter-chains.md`)
  makes the explicit-import pattern the source of truth.
- `@ConditionalOnProperty` gates on configuration classes have no activation effect while the
  classes are not auto-registered. They remain in place for when auto-configuration is
  re-enabled, but hosts must not rely on them for activation control — the `@Import` list (or
  umbrella opt-in) is the actual gate today.
- The deployment-strategy activation model (`camunda.security.strategy`) remains an open item;
  filter-chain activation and deployment-strategy selection are decided independently until that
  work lands.

## Alternatives Considered

- **Keep auto-configuration, gate everything tightly with `@ConditionalOnProperty`.** Rejected —
  the root problem is that the library is not finished, not that the conditions are too
  permissive. Even a perfectly gated condition can be accidentally satisfied by a host's property
  file. Explicit opt-in is safer than better-guarded implicit opt-in.
- **Plain `@Configuration` classes with no library-supplied beans, hosts construct everything.**
  Rejected — every host runs the same auth-method/API-protection matrix, so composing it by hand
  is ceremony rather than signal, and it forces every consumer to reconstruct `JwtDecoder`,
  `ClientRegistrationRepository`, and the OAuth2 client beans identically. The chosen model keeps
  the library-supplied defaults (via `@ConditionalOnMissingBean`) while still requiring an
  explicit, visible activation step per host.

Consolidates records previously numbered 0006 (see git history).
