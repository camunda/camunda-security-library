---
status: Accepted
---

# ADR-0025: `CamundaSecurityScopeProvider` SPI for host-contributed path-scoped API chains

**Deciders**: Ben Sheppard (Ben-Sheppard), Patrick Wunderlich (p-wunderlich), Sebastian Bathke (megglos)

## Status

Accepted

## Context

CSL owns the standard API and webapp security filter chains for every Camunda host application
(see [ADR-0006](0006-central-security-filter-chains.md)). Those chains cover the host's
primary API surface (e.g. `/v2/**`) with a single, shared `JwtDecoder` and `ClientRegistration`.

Certain host deployments need to expose additional path-scoped API surfaces — each with its own
isolated provider set — protected with the same kind of enforcement CSL already applies to the
primary chain (OIDC bearer-token validation, or HTTP Basic). The isolation that matters is the
provider set: a token issued for one scope's providers must not authenticate against a scope that
carries only different providers. This is a security property; a single shared decoder that merged
all providers would weaken it.

CSL builds each scope's chain from the authentication method declared on its descriptor, and is
agnostic to how that method relates to the primary chain or to other scopes. A scope's method is
fully independent of the cluster's global `camunda.security.authentication.method`; an OIDC-scoped
descriptor works even when the global method is `basic`. If a deployment requires a single
consistent method across all its scopes, that is a host-side constraint the host is responsible for
(for example, via configuration validation) — CSL neither assumes nor enforces it. Keeping CSL out
of that concern keeps the SPI simple.

Before this change, a host that needed such a surface had to assemble a `SecurityFilterChain`
bean by hand, duplicating the CSL chain shape, the hardened HTTP-header defaults, CSRF wiring, and
the decoder selection logic. Each duplication is a future drift risk: improvements to CSL's chain
assembly (new headers, CSRF rule changes, logging) do not automatically propagate to hand-rolled
host chains.

CSL is scope-agnostic: it should not learn what a scope *means* to the host — that is a host
concern. What CSL can own is the chain-assembly mechanics.

The question this ADR answers: what SPI shape lets hosts contribute path-scoped API chains while
keeping CSL agnostic of scope semantics, and owning chain assembly as a single source of truth?

## Decision

### SPI and descriptor

A new inbound SPI `CamundaSecurityScopeProvider` is added to `api/context/`:

```java
public interface CamundaSecurityScopeProvider {
  List<ScopedSecurityDescriptor> get();
}
```

The descriptor lives in `api/model/config/`:

```java
public record ScopedSecurityDescriptor(
    String basePath, AuthenticationConfiguration authentication) { ... }
```

`basePath` is the scope's path prefix; CSL derives the chain's security matchers by prefixing
each entry from `SecurityPathPort.apiPaths()` (and `SecurityPathPort.unprotectedApiPaths()`) with
`basePath`. The API surface is therefore host-defined: when a host's `apiPaths()` is `{"/v2/**"}`,
the scoped matcher becomes `basePath + "/v2/**"`; a host with `{"/api/**"}` produces
`basePath + "/api/**"` instead. This keeps the descriptor surface-agnostic: if a future webapp
surface is needed for the same scope, the descriptor is reused unchanged and CSL assembles a
different chain type from it.

The compact constructor rejects a null/blank `basePath` and a null `authentication` at
construction time.

### Reusable builders (single source of truth)

Chain assembly is factored into three reusable helpers in `spring-boot-starter`:

- **`ScopedClientRegistrationFactory`** — flattens an `AuthenticationConfiguration` (flat `oidc.*`
  block and/or `providers.oidc.*` map) into `ClientRegistration` instances using the same merge
  rule as `OidcAuthenticationConfigurationRepository`. This is the single authoritative
  implementation of that merge; `OidcAuthenticationConfigurationRepository` delegates here instead
  of duplicating it.

- **`ScopedJwtDecoderFactory`** — builds a `JwtDecoder` from an `AuthenticationConfiguration` by
  delegating to `ScopedClientRegistrationFactory` and `OidcAccessTokenDecoderFactory`. When the
  configuration carries a single provider, a single-issuer decoder is produced; when it carries
  multiple providers, the issuer-aware decoder from [ADR-0020](0020-issuer-aware-jwt-decoder.md)
  is selected. A scope-specific `TokenValidatorFactory` is built from the scope's merged provider
  map and threaded into the decoder, so both issuer and audience validation are enforced using the
  scope's own configuration. Structural isolation is the result: a token whose `iss` claim matches
  no provider in the scope fails with a `BadJwtException`; a token whose `aud` claim does not
  satisfy the scope's configured audiences is also rejected — even when two scopes share the same
  issuer (shared-IdP / physical-tenant isolation). The unknown-issuer message names the offending
  issuer to aid diagnosis.

- **`ScopedApiSecurityChainBuilder`** — the single source of truth for the CSL API chain shape.
  It exposes three methods:
  - `buildOidcApiChain(HttpSecurity, matchers, unprotectedMatchers, JwtDecoder)` — the OIDC
    resource-server chain: session stateless, no form login, no anonymous, CSRF and secure-headers
    applied.
  - `buildBasicApiChain(HttpSecurity, matchers, unprotectedMatchers)` — the HTTP Basic chain with
    the same stateless/secure-headers baseline.
  - `buildScopedApiChain(HttpSecurity, basePath, AuthenticationConfiguration, Supplier<JwtDecoder>)`
    — selects OIDC or Basic by `authentication.getMethod()` and derives the chain's security
    matchers by prefixing each entry from `SecurityPathPort.apiPaths()` and
    `SecurityPathPort.unprotectedApiPaths()` with `basePath`. The API surface is host-defined,
    not fixed to `/v2/**`.

  CSL's own `OidcApiSecurityConfiguration` and `BasicAuthApiSecurityConfiguration` are re-based on
  `ScopedApiSecurityChainBuilder`. Any future change to the chain shape (new headers, CSRF rule,
  logging) is made once and propagates to both the primary chains and every scope-contributed chain.

### Collector: `ScopedApiSecurityConfiguration`

A new `@Configuration` class `ScopedApiSecurityConfiguration` in `spring-boot-starter` collects
all `CamundaSecurityScopeProvider` beans and registers one `SecurityFilterChain` bean definition
per descriptor.

The collector uses a `BeanDefinitionRegistryPostProcessor` (BDRPP) declared as a `static @Bean`.
The `static` declaration is required: it causes Spring to instantiate the post-processor before
the enclosing `@Configuration` class is constructed, avoiding the "configuration class created
too early" warning. At that point, host `@Configuration` parsing has already completed and
provider beans are registered in the registry, so the BDRPP can call `getBean` on each provider
to enumerate descriptors.

**Important caveat (also documented in the adopter guide):** because the BDRPP calls `getBean`
on each `CamundaSecurityScopeProvider` during bean-definition registration, a provider declared
as a non-static `@Bean` on a `@Configuration` with inter-`@Bean` method references will be
instantiated before CGLIB enhancement completes. Spring logs:

> "Cannot enhance @Configuration bean definition ... created too early"

and the configuration class loses CGLIB proxy behaviour — inter-`@Bean` calls will not route
through the Spring container. Hosts **must** declare their `CamundaSecurityScopeProvider` as one
of:

- a `static @Bean` on the host `@Configuration`, or
- a `@Bean` on a `@Configuration(proxyBeanMethods = false)` class, or
- a standalone `@Component` / `@Service` bean without inter-bean method references.

### `OrderedSecurityFilterChainWrapper` and chain ordering

`DefaultSecurityFilterChain` (the type Spring Security's `HttpSecurity.build()` returns) does not
implement `Ordered`, and registering bean-definition order attributes does not affect how
`FilterChainProxy` sequences chains at request time — Spring Security sorts chains by the
`Ordered` interface, not by bean-registration order. A chain with no order sorts last, behind the
catch-all deny chain, which would make every contributed request 404/denied.

To give host-contributed chains a defined position, each registered chain is wrapped in
`OrderedSecurityFilterChainWrapper implements SecurityFilterChain, Ordered`. The wrapper returns
`ORDER_WEBAPP_API` from `getOrder()` — contributed chains **reuse the primary API order rather than
a dedicated band**. This is deliberate: their base paths are structurally disjoint from CSL's own
matchers (a request matches at most one chain regardless of relative order), so the only ordering
requirement is that they sort before the `ORDER_UNHANDLED` catch-all deny chain. Introducing a
separate order value would add a constant without buying any correctness.

The filter chain order is:

| Constant | Value | Chain |
|---|---|---|
| `ORDER_UNPROTECTED` | `0` | Permit-all unprotected-paths chain |
| `ORDER_WEBAPP_API` | `1` | Primary API and webapp chains, and host-contributed scope chains |
| `ORDER_UNHANDLED` | `2` | Catch-all deny chain |

### Per-scope OIDC infrastructure

The per-scope OIDC factories (`JWSKeySelectorFactory`, `ScopedClientRegistrationFactory`,
`OidcAccessTokenDecoderFactory`, `ScopedJwtDecoderFactory`) are provided by the unconditional
`ScopedOidcInfrastructureConfiguration`. They do not depend on the cluster's global authentication
method and are available regardless of whether `OidcBeansConfiguration` is active. This means a
host can contribute an OIDC-scoped descriptor while running the cluster in global `basic` mode.

The injected `TokenValidatorFactory` inside `OidcAccessTokenDecoderFactory` uses an
`ObjectProvider` fallback: when the cluster is in global OIDC mode, the global
`TokenValidatorFactory` (built from the full provider list by `OidcBeansConfiguration`) is
injected; otherwise an empty-provider default is used. This default has no effect on per-scope
validation — each scope always builds its own `TokenValidatorFactory` seeded with its own provider
map inside `ScopedJwtDecoderFactory.buildIssuerAwareDecoder`.

### Activation

`ScopedApiSecurityConfiguration` and `ScopedOidcInfrastructureConfiguration` are both added to
the umbrella `CamundaSecurityAutoConfiguration`'s `@Import` list (see
[ADR-0008](0008-no-spring-boot-auto-configuration.md)). No action is required when no
`CamundaSecurityScopeProvider` bean is present — the BDRPP finds zero providers and registers
nothing. Hub and single-scope OC hosts are unchanged.

Hosts that do not use the umbrella but import CSL configurations individually must add
`ScopedApiSecurityConfiguration.class` and `ScopedOidcInfrastructureConfiguration.class` to their
`@Import` list if they want scope-contributed chains.

## Consequences

**Positive**

- CSL is the single source of truth for API chain assembly. CSRF rules, HTTP security headers, and
  auth-failure handling are updated in one place and propagate to all chains — host-contributed
  and CSL-owned — without any host change.
- Structural token isolation is the default. Each scope's decoder is built from a per-scope
  `TokenValidatorFactory` seeded with that scope's providers. A wrong issuer fails at decode with
  an informative message; a mismatched audience fails too — including when two scopes share the
  same issuer but configure different audiences (shared-IdP / physical-tenant isolation).
- Additive and backward-compatible. Hosts without a `CamundaSecurityScopeProvider` bean are
  unaffected; the BDRPP is a no-op. No renaming or configuration changes to existing deployments.
- Aligns with [ADR-0008](0008-no-spring-boot-auto-configuration.md): the collector activates only
  through the umbrella or an explicit `@Import` — nothing activates from the Maven dependency
  alone.
- Reuses the issuer-aware decoder from [ADR-0020](0020-issuer-aware-jwt-decoder.md) for per-scope
  multi-provider validation without duplicating the selection logic.

**Negative / accepted trade-offs**

- Hosts must declare their `CamundaSecurityScopeProvider` as a `static @Bean`, on a
  `@Configuration(proxyBeanMethods = false)`, or as a standalone component to avoid the CGLIB
  "created too early" warning and loss of config-class enhancement. A non-static `@Bean` on a
  `@Configuration` with inter-`@Bean` references will silently lose CGLIB proxy behaviour; no
  exception is thrown, making the issue hard to diagnose without reading Spring's startup logs.
- One `SecurityFilterChain` bean definition is registered per descriptor. A host with N scopes
  contributes N additional filter chains. For small N this is negligible; very large N is not a
  known use case.
- The descriptor calls `getBean` during `postProcessBeanDefinitionRegistry`, which means the
  `CamundaSecurityScopeProvider` bean (and any beans it directly depends on) is instantiated
  earlier in the context lifecycle than normal. Provider implementations must not depend on beans
  that require a fully refreshed context.

## Alternatives Considered

- **Host builds finished chains inline.** Each host that needs scope-isolated chains assembles its
  own `SecurityFilterChain` bean, duplicating the CSL chain shape. Rejected — every copy is a
  future drift risk: hardening applied to CSL's own chains (new HTTP headers, CSRF rule changes,
  failure-logging improvements) does not propagate. The SPI solves this permanently.

- **A single scope-aware dispatching chain instead of N chains.** One CSL-owned chain inspects the
  request path at request time, selects the correct decoder, and dispatches. Deferred — the
  descriptor model already makes this possible as a future optimisation (enumerate descriptors at
  startup, build one chain that routes by path prefix) without changing the host contract.
  N distinct chains are simpler to reason about and audit individually; the deferred approach can
  be adopted later if N grows large enough to warrant it.

- **Ordering via `@Order` or bean-definition order attributes.** Register each `SecurityFilterChain`
  bean with `@Order` or set the bean-definition's `order` attribute. Rejected —
  `FilterChainProxy` orders chains by the `Ordered` interface at runtime, not by bean-definition
  order or `@Order` annotations. `DefaultSecurityFilterChain` does not implement `Ordered`, so
  without the `OrderedSecurityFilterChainWrapper` the chains would not have a predictable position
  relative to the catch-all deny chain.
