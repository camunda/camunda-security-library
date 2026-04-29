---
status: Accepted
---

# ADR-0006: Central Spring Security filter chains as Spring Boot auto-configuration

## Status

Accepted

## Context

The CSL is embedded into multiple host applications (Hub, Orchestration Cluster gateways) that have historically maintained their own Spring Security configurations. This duplicated:

- API/webapp securityMatcher wiring per host,
- OIDC and Basic-auth filter chain plumbing,
- CSRF protection logic, hardened HTTP response headers, OAuth2 refresh-token handling.

Inconsistencies between host configurations have repeatedly produced security regressions — different CSP defaults, missing CSRF, divergent failure-handler behaviour, drift between OIDC API and webapp chains. Centralising this logic in the CSL is a prerequisite for the "always-on AuthN/AuthZ enforcement" guarantee in [ADR-0002](0002-placement-of-the-security-gateway-framework.md).

The original spike for this work (`spike/new-replacement-auth-lib` in the monorepo) shipped the chains as a single `@AutoConfiguration` class. Early in the extraction we briefly tried a plain `@Configuration` design with `@Import` composition — hosts would `@Import` exactly the chains they wanted, and the library would supply zero default beans. That design assumed two things that turned out to be wrong:

1. **It assumed hosts should know which chains to import.** In practice, every host runs a flavour of the same configuration matrix (auth method × API protected/unprotected). The choice is data, not code — driving it from the host's class graph forced every adopter to repeat the same `@Import` ceremony and read the library's source to know what to wire.
2. **It assumed the library shouldn't supply runtime beans like `JwtDecoder` or `ClientRegistrationRepository`.** Every Camunda host needs the same beans, built from the same property surface, with the same defaults. Asking each adopter to construct them by hand multiplied the same code across every consumer for no benefit.

Spring Boot auto-configuration solves both problems out of the box. The remaining concern — that auto-configuration locks the library to Spring Boot — is real but bounded: every current and planned Camunda host runs Spring Boot. A future "library usable in plain Spring or non-Spring contexts" effort can layer a non-Boot extraction on top later without disturbing the Spring Boot path.

The core question for this ADR is:

> How do we expose the centralised filter chain logic so that any Camunda host can adopt it with minimum wiring while still allowing host-specific overrides?

## Decision

We will:

- Ship the filter chains and supporting beans as **Spring Boot auto-configurations** in a `camunda-security-library-spring-boot-starter` artefact, registered through `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.
- Activate each chain via `@ConditionalOnProperty` (or, for chains that depend on more than one property, a small `@Conditional` class with the same semantics). Hosts opt in by setting `camunda.security.authentication.method=oidc|basic` (and friends) — they never touch `@Import`.
- Provide library-supplied default beans for `JwtDecoder`, `ClientRegistrationRepository`, `OAuth2AuthorizedClientRepository`, `OAuth2AuthorizedClientManager`, and a default `AuthFailureHandler` (`JsonProblemDetailAuthFailureHandler`). Each has `@ConditionalOnMissingBean` so a host that registers its own bean with the same type takes precedence.
- Define the host-facing contract through `SecurityPathAdapter` (in `csl-core`) plus the existing OAuth2 extension hooks (`OidcTokenEndpointCustomizer`, `OidcResourceServerCustomizer`). Hosts register beans of those types; the library picks them up via `ObjectProvider`. Host-specific filter wiring is deliberately not addressed by this PR — a follow-up will introduce a more focused mechanism than a generic `HttpSecurity` mutator.
- Bind all configuration through one `@ConfigurationProperties("camunda.security")` POJO (`CamundaSecurityLibraryProperties`) covering authentication, CSRF, and HTTP response headers.

The chain auto-configurations are:

| Class | Activation |
|---|---|
| `BaseSecurityAutoConfiguration` | always — unprotected paths chain + catch-all deny chain |
| `OidcApiSecurityAutoConfiguration` | `method=oidc` AND `unprotected-api` is not `true` |
| `OidcWebappSecurityAutoConfiguration` | `method=oidc` |
| `BasicAuthApiSecurityAutoConfiguration` | `method=basic` AND `unprotected-api` is not `true` |
| `BasicAuthWebappSecurityAutoConfiguration` | `method=basic` |
| `UnprotectedApiSecurityAutoConfiguration` | `unprotected-api=true` (development-only; logs a startup warning) |

Plus `OidcBeansAutoConfiguration` (the OIDC default beans, gated on `method=oidc`) and `AuthFailureHandlerAutoConfiguration`.

## Options considered

### Option 1 — Spring Boot auto-configuration with property-driven activation (chosen)

- Shape:
  - Each chain is an `@AutoConfiguration` class registered via `META-INF/spring/...AutoConfiguration.imports`.
  - `@ConditionalOnProperty` (or a small `@Conditional`) on each class encodes the activation rule.
  - Library provides default `JwtDecoder`, `ClientRegistrationRepository`, OAuth2 client beans and the default `AuthFailureHandler` behind `@ConditionalOnMissingBean`.
  - Hosts include the dep, set properties, and the right chains plus their dependencies wire automatically. Hosts override any of the library beans by registering their own.
- Pros:
  - Adopting the library is "include the dep, set `camunda.security.authentication.method`, supply a `SecurityPathAdapter`."
  - A single source of truth for configuration: `camunda.security.*` properties drive activation; no separate compile-time wiring to keep in sync with runtime config.
  - Library defaults eliminate per-host bean duplication while still allowing overrides at any specific layer.
  - Plays well with Spring Boot's existing autoconfig (`JacksonAutoConfiguration` provides the `ObjectMapper` the failure handler consumes; `SecurityAutoConfiguration` doesn't conflict because the library's chains are explicit `@Bean`s).
- Cons:
  - Locks the library to Spring Boot for the chain wiring. A future non-Boot consumer needs a different distribution path — see *Consequences*.
  - Activation is property-driven, so a misspelled property silently leaves a chain off. Mitigated by tests that assert each property surface and by the documented adopter guide.

### Option 2 — Plain `@Configuration` classes hosts `@Import` (rejected; previous design)

- Shape:
  - Each chain is a plain `@Configuration` class with `@Bean SecurityFilterChain` methods.
  - Hosts compose: `@Import({BaseSecurityConfig.class, OidcApiSecurityConfig.class, ...})`.
  - Library supplies no runtime beans (no `JwtDecoder`, no `ClientRegistrationRepository`); hosts construct them.
- Pros:
  - No `spring-boot-autoconfigure` dependency.
  - Activation is explicit in the host's class graph.
- Cons:
  - Every host runs the same activation matrix, so the explicit imports are ceremony, not signal.
  - Host integrators have to read the library's source (or its adopter doc) to know which chains to import for which auth method — a discovery burden the library shouldn't impose.
  - "No library beans" forces every consumer to construct `JwtDecoder` / `ClientRegistrationRepository` / OAuth2 client beans the same way, repeating the same code in N hosts.
  - The ergonomics of hosts having to wire boring infrastructure repeatedly outweighs the abstract benefit of being non-Boot-friendly.

This was the v1 design in this PR. We reversed before merging.

### Option 3 — Programmatic builder API (rejected)

- Shape:
  - `CamundaSecurity.builder()` API returns one or more configured `SecurityFilterChain` instances; hosts register them as beans by hand.
- Pros:
  - Maximally container-agnostic; usable in any servlet context.
  - No reliance on Spring's bean composition model.
- Cons:
  - Loses the Spring-native composition (`HttpSecurity` shared customisation, `ObjectProvider`-based optional dependencies, `@ConditionalOnMissingBean` overriding through the bean container).
  - Reinvents what `@Configuration` already provides.
  - Every Spring host would still want a Spring-flavoured wrapper, growing the maintenance surface.

## Consequences

- **Adopting hosts get a one-line story:** include the dep, set properties (auth method, OIDC settings if any), supply a `SecurityPathAdapter` bean. Everything else is library-provided defaults that the host can override per bean if needed. The adopter guide at `docs/adopters/security-filter-chains.md` walks through the property surface.
- **Library is committed to Spring Boot for this slice.** Non-Spring-Boot consumers are out of scope; a follow-up effort can extract the filter chain logic into a Spring-only or non-Spring distribution that a Boot starter wraps. That extraction does not require redesigning the chains — only the wiring layer.
- **Configuration consistency moves from the class graph to property files.** A misspelled `camunda.security.authentication.method` value silently leaves chains off. The library's auto-configuration tests cover the activation conditions explicitly so regressions surface in CI; hosts can add a smoke test that asserts the expected `SecurityFilterChain` beans are present at startup.
- **Library defaults reduce per-host duplication.** `JwtDecoder` is built from `camunda.security.authentication.oidc.*` properties; same for `ClientRegistrationRepository` and the OAuth2 client beans. A host that needs a different shape (multi-IdP, custom token validator, private_key_jwt) registers its own bean and the library's default backs off.
- **CSRF, secure headers, refresh-token, and failure-handler behaviour are uniform across hosts.** Host configurations can no longer drift on these baselines.
- **The `Strategy` enum (`oc-standalone`/`oc-managed`/`hub`) and the `camunda.security.strategy` property are deferred.** Strategy is a policy concern (not an authentication concern) and belongs to the policy work tracked separately. The library does not require it for filter-chain activation today.
- **ADR-0006 supersedes its own earlier draft within this PR.** No older form of this ADR ever shipped on `main`; the rewrite is in-PR.
