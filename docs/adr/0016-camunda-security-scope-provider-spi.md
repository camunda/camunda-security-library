---
status: Accepted
---

# ADR-0016: `CamundaSecurityScopeProvider` SPI for host-contributed path-scoped API and webapp chains

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

CSL owns the standard API and webapp security filter chains for every Camunda host application (see
[ADR-0006](0006-no-spring-boot-auto-configuration.md) for how a host activates them). Those chains
cover the host's primary surfaces (e.g. `/v2/**` for the API) with a single shared `JwtDecoder` and
`ClientRegistration` set.

Certain host deployments need to expose additional **path-scoped** surfaces — each with its own
isolated provider set — protected with the same kind of enforcement CSL already applies to the
primary chains. The motivating case is a Camunda 8 Orchestration Cluster running *physical tenants*:
many isolated tenants behind per-tenant URL prefixes. The isolation that matters is the provider set:
a token issued for one scope's providers must not authenticate against a scope that carries only
different providers. This is a security property; a single shared decoder that merged all providers
would weaken it.

Both surfaces are needed per scope, and the interactive one is materially harder:

- An **API** chain is stateless: bearer-token validation (or HTTP Basic), no session.
- A **webapp** chain is interactive: OAuth2 authorization-code login (`oauth2Login`), the multi-IdP
  login picker, logout, and a browser session — plus, in BASIC mode, form login. `oauth2Login`
  requires an HTTP session to hold the `SecurityContext` and the authorization-request state, so a
  scoped webapp chain drags in session and cookie isolation as well.

Before this change, a host that needed such a surface had to assemble `SecurityFilterChain` beans by
hand, duplicating the CSL chain shape, the hardened HTTP-header defaults, CSRF wiring, and the
decoder selection logic. Each duplication is a future drift risk: improvements to CSL's chain
assembly (new headers, CSRF rule changes, logging) do not automatically propagate to hand-rolled host
chains.

The hard constraint is that **CSL must remain scope-agnostic**: it must not learn what a scope
*means* to the host — that is a host concern. What CSL can own is the chain-assembly mechanics. CSL
builds each scope's chain from the authentication method declared on its descriptor and is agnostic
to how that method relates to the primary chain or to other scopes. A scope's method is fully
independent of the cluster's global `camunda.security.authentication.method`; an OIDC-scoped
descriptor works even when the global method is `basic`. If a deployment requires one consistent
method across all its scopes, that is a host-side constraint the host enforces (for example via
configuration validation) — CSL neither assumes nor enforces it. Keeping CSL out of that concern
keeps the SPI simple.

The question this ADR answers: what SPI shape lets hosts contribute path-scoped **API and webapp**
chains while keeping CSL agnostic of scope semantics, and owning chain assembly as a single source of
truth?

## Decision

### 1. SPI and descriptor

An inbound SPI `CamundaSecurityScopeProvider` in `api/context/`:

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

`basePath` is the scope's path prefix; its compact constructor rejects a null/blank `basePath` and a
null `authentication` at construction time. CSL derives every matcher and every endpoint from
`basePath` and the host's `SecurityPathPort`:

- API matchers: each entry from `SecurityPathPort.apiPaths()` and
  `SecurityPathPort.unprotectedApiPaths()` prefixed with `basePath`. The API surface is therefore
  host-defined: a host whose `apiPaths()` is `{"/v2/**"}` gets `basePath + "/v2/**"`; a host with
  `{"/api/**"}` gets `basePath + "/api/**"`.
- Webapp matchers: each entry from `SecurityPathPort.webappPaths()` prefixed with `basePath`.
- Webapp endpoints: login at `basePath + /login`, logout at `basePath + /logout`, the OAuth2
  authorization base URI at `basePath + /oauth2/authorization`, and the redirection endpoint derived
  from the configured client `redirect-uri` (defaulting to `/sso-callback`, see
  [ADR-0021](0021-optimize-reuses-stateful-oidc-webapp-chain.md)).

**No surface-specific field is ever added to the descriptor.** That is what keeps the same descriptor
usable for both chain types, and it is why the per-scope session cookie name and the post-logout
route are derived or declared elsewhere rather than carried on the descriptor
([ADR-0012](0012-session-store-port-and-web-session-ownership.md)).

### 2. Reusable builders — one source of truth per chain shape

Chain assembly is factored into reusable helpers in `spring-boot-starter`, each of which CSL's *own*
primary chains are also built from, so no shape exists in two places:

- **`ScopedClientRegistrationFactory`** — flattens an `AuthenticationConfiguration` (flat `oidc.*`
  block and/or `providers.oidc.*` map) into `ClientRegistration` instances. This is the single
  authoritative implementation of that merge rule; `OidcAuthenticationConfigurationRepository`
  delegates here instead of duplicating it.

- **`ScopedJwtDecoderFactory`** — builds a `JwtDecoder` from an `AuthenticationConfiguration` by
  delegating to `ScopedClientRegistrationFactory` and `OidcAccessTokenDecoderFactory`. A single
  configured provider yields a single-issuer decoder; several providers select the issuer-aware
  decoder of [ADR-0009](0009-multi-idp-oidc-configuration.md). A scope-specific
  `TokenValidatorFactory` is built from the scope's merged provider map and threaded into the
  decoder, so both issuer and audience validation use the scope's own configuration. Structural
  isolation is the result: a token whose `iss` claim matches no provider in the scope fails with a
  `BadJwtException`, and a token whose `aud` claim does not satisfy the scope's configured audiences
  is rejected too — even when two scopes share the same issuer (shared-IdP isolation). The
  unknown-issuer message names the offending issuer to aid diagnosis.

- **`ScopedApiSecurityChainBuilder`** — the single source of truth for the CSL API chain shape:
  `buildOidcApiChain` (resource-server chain: stateless session policy, no form login, no anonymous,
  CSRF and secure headers applied), `buildBasicApiChain` (HTTP Basic on the same baseline),
  `buildScopedApiChain` (selects OIDC or Basic by `authentication.getMethod()` and prefixes the
  host's API matchers with `basePath`), and `buildUnprotectedScopedApiChain` (the permit-all
  dev-mode variant for a scope). Each has primary-chain and scoped overloads; CSL's own
  `OidcApiSecurityConfiguration` and `BasicAuthApiSecurityConfiguration` are built on it.

- **`ScopedWebappSecurityChainBuilder`** — the webapp sibling, symmetric to the API builder and the
  single source of truth for the CSL webapp chain shape. By `authentication.getMethod()` it
  assembles either:
  - **OIDC** — `oauth2Login` with the scope's `ClientRegistration`s (from the descriptor's merged
    configuration via `ScopedClientRegistrationFactory`, i.e. the scope's assigned providers only);
    the multi-IdP login picker at `basePath + /login`; the redirection endpoint; logout at
    `basePath + /logout`; and the delegating `AuthenticationEntryPoint` (bearer → 401, browser →
    IdP/login) retained per [ADR-0014](0014-oidc-bearer-tokens-on-api-chain-only.md);
  - **BASIC** — form login at `basePath + /login` backed by the host's `BasicAuthUserDetailsPort`
    ([ADR-0013](0013-user-details-port.md)), whose adapter resolves the scope from request context.

  CSL's own `OidcWebappSecurityConfiguration` and `BasicAuthWebappSecurityConfiguration` are built on
  this builder, so the webapp surface has the same single-source-of-truth property the API surface
  has: any change to the chain shape (new headers, CSRF rule, logging) is made once and propagates to
  the primary chains and every scope-contributed chain alike.

Session components (per-scope `SessionRepositoryFilter`, cookie serializers, the post-logout
handler) are handed to these builders rather than created by them; their ownership and isolation
rules are [ADR-0012](0012-session-store-port-and-web-session-ownership.md)'s.

### 3. Prefix-aware authorization-request resolver

Spring Security's default `OAuth2AuthorizationRequestResolver` does not reliably match a
multi-segment prefix such as `basePath + /oauth2/authorization/<id>`. Scoped webapp chains therefore
install `CamundaOidcAuthorizationRequestResolver`, a prefix-aware implementation, so the
authorization request and the scoped redirection endpoint resolve correctly. It composes with the
resolver CSL already owns for the primary chain (RFC 8707 `resource`, additional parameters).

### 4. Collector and registrar

`ScopedSecurityChainConfiguration` (`spring-boot-starter`, package `io.camunda.security.spring.scope`)
is the `@Configuration` entry point. It `@Import`s the builder configurations it needs
(`ScopedApiSecurityChainBuilderConfiguration`, `ScopedWebappSecurityChainBuilderConfiguration`,
`ScopedOidcInfrastructureConfiguration`) so a host that imports only this one class still gets a
working scope subsystem, and it declares `ScopedSecurityChainRegistrar` — a
`BeanDefinitionRegistryPostProcessor` (BDRPP) — as a **`static @Bean`**.

The registrar collects all `CamundaSecurityScopeProvider` beans and registers, **per descriptor, both
an API and a webapp chain** (method-driven; a descriptor is single-mode, so each chain is OIDC or
Basic, never both). It also enforces the startup fail-fast checks: duplicate `basePath` rejection and
the derived-cookie-name checks described in ADR-0012.

The `static` declaration is required: it makes Spring instantiate the post-processor before the
enclosing `@Configuration` class is constructed, avoiding the "configuration class created too early"
warning for CSL's own class. At that point host `@Configuration` parsing has already completed and
provider beans are registered in the registry, so the BDRPP can call `getBean` on each provider to
enumerate descriptors.

> **Warning — the single riskiest trap in this design for a host implementer.** Because the registrar
> calls `getBean` on each `CamundaSecurityScopeProvider` during bean-definition registration, a
> provider declared as a non-`static` `@Bean` on a `@Configuration` class that uses inter-`@Bean`
> method references will be instantiated *before* CGLIB enhancement of that configuration class
> completes. Spring logs
>
> > "Cannot enhance @Configuration bean definition ... created too early"
>
> and the configuration class loses CGLIB proxy behaviour — inter-`@Bean` calls no longer route
> through the Spring container, so what looked like a singleton reference silently becomes a fresh
> object. **No exception is thrown.** The failure is silent and hard to diagnose without reading
> Spring's startup logs.
>
> Hosts **must** declare their `CamundaSecurityScopeProvider` as one of:
>
> - a `static @Bean` on the host `@Configuration`, or
> - a `@Bean` on a `@Configuration(proxyBeanMethods = false)` class, or
> - a standalone `@Component` / `@Service` bean with no inter-bean method references.
>
> This is also documented in the adopter guide.

### 5. `OrderedSecurityFilterChainWrapper` and chain ordering

`DefaultSecurityFilterChain` (the type `HttpSecurity.build()` returns) does not implement `Ordered`,
and bean-definition order attributes or `@Order` annotations do not affect how `FilterChainProxy`
sequences chains at request time — Spring Security sorts by the `Ordered` interface. A chain with no
order sorts last, behind the catch-all deny chain, which would make every contributed request
404/denied. Each registered chain is therefore wrapped in `OrderedSecurityFilterChainWrapper
implements SecurityFilterChain, Ordered`.

Host-contributed API chains and host-contributed webapp chains get **distinct** order values —
`ORDER_API` and `ORDER_WEBAPP` respectively — rather than sharing one constant. Keeping the API chain
ahead of the webapp chain matters when a webapp matcher is a catch-all: a scoped catch-all webapp
matcher must not claim API requests ahead of the scoped API chain. Beyond that, ordering only has to
sort **ahead of the `ORDER_UNHANDLED` catch-all deny chain**; scope base paths are structurally
disjoint from CSL's own matchers and from each other, so a request matches at most one chain
regardless of relative order.

| Constant | Value | Chain |
|---|---|---|
| `ORDER_UNPROTECTED` | `0` | Permit-all unprotected-paths chain (incl. the unprotected scoped API variant) |
| `ORDER_API` | `1` | Primary API chains and host-contributed scoped API chains |
| `ORDER_WEBAPP` | `2` | Primary webapp chains and host-contributed scoped webapp chains |
| `ORDER_UNHANDLED` | `3` | Catch-all deny chain |

### 6. Per-scope OIDC infrastructure

The per-scope OIDC factories (`JWSKeySelectorFactory`, `ScopedClientRegistrationFactory`,
`OidcAccessTokenDecoderFactory`, `ScopedJwtDecoderFactory`) are provided by the unconditional
`ScopedOidcInfrastructureConfiguration`. They do not depend on the cluster's global authentication
method and are available whether or not `OidcBeansConfiguration` is active, so a host can contribute
an OIDC-scoped descriptor while running the cluster in global `basic` mode.

The `TokenValidatorFactory` injected into `OidcAccessTokenDecoderFactory` uses an `ObjectProvider`
fallback: in global OIDC mode the global factory (built from the full provider list by
`OidcBeansConfiguration`) is injected, otherwise an empty-provider default is used. That default has
no effect on per-scope validation — each scope always builds its own `TokenValidatorFactory` seeded
with its own provider map inside `ScopedJwtDecoderFactory`.

### 7. Serving the scoped SPA stays host-side

Rewriting a served SPA so it bootstraps under `basePath` (base-href/context-path handling, asset and
cluster-endpoint URL mapping, webapp-controller routing) is a pure host webapp-serving concern: **CSL
never serves the SPA and never learns the prefix scheme.**

### 8. Activation

`ScopedSecurityChainConfiguration` and `ScopedOidcInfrastructureConfiguration` are members of the
umbrella `CamundaSecurityAutoConfiguration`'s `@Import` list (see
[ADR-0006](0006-no-spring-boot-auto-configuration.md)), alongside the two builder configurations. No
action is required when no `CamundaSecurityScopeProvider` bean is present — the registrar finds zero
providers and registers nothing, so primary-only hosts (Hub, single-scope OC) are unaffected. Hosts
that import CSL configurations individually add `ScopedSecurityChainConfiguration.class` and
`ScopedOidcInfrastructureConfiguration.class` to their `@Import` list if they want scope-contributed
chains.

### Why these particular boundaries

- **A surface-agnostic descriptor.** `basePath` plus an `AuthenticationConfiguration` is the minimum
  a host must state, and everything else is derivable. Adding webapp fields (cookie name/path,
  redirect URI, login URL, post-logout route) would leak surface concerns into the host contract and
  would have to be re-opened for every future chain type.
- **Builders shared with CSL's own chains.** If the scoped chains were assembled by separate code,
  the two shapes would drift. Re-basing the primary chains on the same builders makes drift
  impossible by construction, and is why the webapp side was worth the extra builder rather than
  letting hosts assemble webapp chains themselves.
- **A BDRPP rather than a `@Bean` loop.** `SecurityFilterChain` beans must exist as bean
  *definitions*, and the descriptor list is only known once host configuration has been parsed. A
  post-processor is the only hook that sits in that window. The cost is the early-instantiation
  caveat above, which is why it is documented as a hard host requirement rather than a footnote.
- **Ordering by the `Ordered` interface, not annotations.** It is the only mechanism
  `FilterChainProxy` actually honours.

### Default implementations and override boundaries

| Contract | Provided by | Default / absent behaviour |
|---|---|---|
| `CamundaSecurityScopeProvider` | Host (optional) | Absent → registrar is a no-op; only primary chains exist |
| `ScopedSecurityDescriptor` | Host | Validated at construction (non-blank `basePath`, non-null `authentication`) |
| Chain shape (API and webapp, OIDC and Basic) | CSL builders | Not host-overridable; hosts contribute descriptors, not chains |
| Per-scope `JwtDecoder` | CSL (`ScopedJwtDecoderFactory`) | Built from the descriptor's providers only |
| Chain order | CSL (`OrderedSecurityFilterChainWrapper`) | `ORDER_API` / `ORDER_WEBAPP`, ahead of `ORDER_UNHANDLED` |

## Consequences

**Positive**

- CSL is the single source of truth for both API and webapp chain assembly. CSRF rules, HTTP security
  headers, and auth-failure handling are updated in one place and propagate to all chains —
  host-contributed and CSL-owned — without any host change.
- Structural token isolation is the default. Each scope's decoder is built from a per-scope
  `TokenValidatorFactory` seeded with that scope's providers. A wrong issuer fails at decode with an
  informative message; a mismatched audience fails too, including when two scopes share an issuer but
  configure different audiences.
- Additive and backward-compatible. Hosts without a `CamundaSecurityScopeProvider` bean are
  unaffected; the registrar is a no-op. No renaming or configuration changes to existing deployments.
- Aligns with [ADR-0006](0006-no-spring-boot-auto-configuration.md): the collector activates only
  through the umbrella or an explicit `@Import` — nothing activates from the Maven dependency alone.
- Reuses the issuer-aware decoder of [ADR-0009](0009-multi-idp-oidc-configuration.md) for per-scope
  multi-provider validation without duplicating the selection logic.

**Negative / accepted trade-offs**

- Hosts must declare their `CamundaSecurityScopeProvider` as a `static @Bean`, on a
  `@Configuration(proxyBeanMethods = false)`, or as a standalone component. A non-static `@Bean` on a
  `@Configuration` with inter-`@Bean` references silently loses CGLIB proxy behaviour with **no
  exception thrown**, making the issue hard to diagnose.
- Provider beans (and any beans they directly depend on) are instantiated earlier in the context
  lifecycle than normal, because the registrar calls `getBean` during
  `postProcessBeanDefinitionRegistry`. Provider implementations must not depend on beans that require
  a fully refreshed context.
- Two `SecurityFilterChain` bean definitions per descriptor, plus that scope's session filter and
  cookie serializers. A host with N scopes contributes 2N chains. Negligible for small N; very large
  N is not a known use case.
- Honouring a browser session on a scoped API chain requires the scope's API surface to be nested
  inside `basePath`; a host that routes it outside the prefix gets bearer-only on that surface (see
  [ADR-0012](0012-session-store-port-and-web-session-ownership.md)).

## Alternatives Considered

- **Hosts assemble finished chains inline.** Each host needing scope-isolated surfaces builds its own
  `SecurityFilterChain` beans, duplicating the CSL chain shape. Rejected — every copy is a future
  drift risk: hardening applied to CSL's own chains (new HTTP headers, CSRF rule changes,
  failure-logging improvements) does not propagate, and for the webapp surface the host would also
  have to re-implement session and cookie isolation. The SPI closes this permanently; CSL owns chain
  assembly, the host owns policy.
- **One scope-aware dispatching chain instead of 2N chains.** A single CSL-owned chain inspects the
  request path at request time, selects the correct decoder and session components, and dispatches.
  Deferred, not rejected outright — the descriptor model already permits it later as an optimisation
  (enumerate descriptors at startup, build one chain that routes by prefix) without changing the host
  contract. N distinct chains are simpler to reason about and to audit individually; the dispatching
  variant becomes attractive only if N grows large enough to warrant it.

Consolidates records previously numbered 0027 (chain-assembly sections only) (see git history).
