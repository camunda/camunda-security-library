---
status: Accepted
---

# ADR-0011: Layer physical-tenant authentication via a single tenant-aware filter chain

**Deciders**: Ben Sheppard, Bojan Mudric

> Initial decider set for the proof-of-concept slice. Additional sign-off from platform and security stakeholders is expected as the design firms up beyond chain-split mechanics. Per the ADR immutability rule in [`.claude/docs/guardrails.md`](../../.claude/docs/guardrails.md), any change in scope or decider composition is captured by a follow-up ADR that supersedes this one, not by edits here.

## Status

Accepted

> Scope of this ADR is the **per-tenant chain shape**: how the library handles requests that arrive at the security layer with a `/physical-tenants/{tenantId}/...` prefix. How non-prefixed requests are handled in Multi-Engine deployments, and how the `default` tenant is resolved, are the subject of [ADR-0012](0012-default-tenant-rewrite-and-implicit-default-tenant.md) — read both together for the full Multi-Engine picture.

## Context

A platform initiative ("physical tenants") introduces tenant-scoped path namespaces of the form `/physical-tenants/{tenantId}/**`, where different tenants may live behind different IDPs with distinct OIDC profiles (issuer, client id, audience, JWK set, etc.) inside the same host process. Feature [#200](https://github.com/camunda/camunda-security-library/issues/200) tracks the work.

The current chain set in [`spring-boot-starter/.../security/`](https://github.com/camunda/camunda-security-library/tree/main/spring-boot-starter/src/main/java/io/camunda/security/spring/security) assumes one IDP / one auth method per deployment. It is composed of:

- `BaseSecurityConfiguration` — unprotected paths (`ORDER_UNPROTECTED = 0`) and a catch-all deny chain (`ORDER_UNHANDLED = 2`).
- One of `OidcWebappSecurityConfiguration`, `BasicAuthWebappSecurityConfiguration`, `OidcApiSecurityConfiguration`, `BasicAuthApiSecurityConfiguration`, or `UnprotectedApiSecurityConfiguration` at `ORDER_WEBAPP_API = 1`, selected by `camunda.security.authentication.method` and `unprotected-api`.

Filter chains in this codebase are uniformly declared as plain `@Bean` methods on `@Configuration` classes per [ADR-0008](0008-no-spring-boot-auto-configuration.md). There is no precedent for programmatic bean registration anywhere in `spring-boot-starter`. `ObjectProvider<T>` is used only to collect customizers, not to produce sets of chains.

The product constraint is that a single deployment is method-homogeneous: every tenant uses OIDC, or every tenant uses basic. Mixed-method deployments are out of scope. Adopters consume only released versions (`SNAPSHOT`s are not used), so any change here must be additive on the consumer-facing surface guarded by [#198](https://github.com/camunda/camunda-security-library/issues/198) / [#199](https://github.com/camunda/camunda-security-library/issues/199).

A naïve reading of "split chains by physical tenant" suggests one `SecurityFilterChain` bean per `(tenantId, method, surface)` triple. With a static-but-N-tenant list, that requires either a `BeanDefinitionRegistryPostProcessor` (no precedent in the codebase) or a `@Bean` method returning `List<SecurityFilterChain>` (which Spring registers as a single bean of type `List`, not as its elements — `FilterChainProxy` does not unpack). Both options either import an unfamiliar Spring discipline or fight Spring's bean model.

Spring Security itself ships a first-class pattern for multi-tenant resource servers: an `AuthenticationManagerResolver<HttpServletRequest>` (or the specialised `JwtIssuerAuthenticationManagerResolver`) that selects the per-tenant `AuthenticationManager` per request inside a single `SecurityFilterChain`. The tenant set is still bound from `@ConfigurationProperties`; it is consumed inside the resolver rather than at bean-definition time.

The core question for this ADR is:

> What chain-layer shape lets us serve `/physical-tenants/{tenantId}/**` with per-tenant IDP isolation, alongside the existing top-level chains, using only the Spring patterns this codebase already adopts?

## Decision

A single tenant-aware `SecurityFilterChain` is added per surface. It sits at a new `@Order` band strictly between `ORDER_UNPROTECTED` and the existing top-level webapp/api chains, and dispatches per-tenant authentication via an `AuthenticationManagerResolver<HttpServletRequest>` whose lookup key is the tenant id extracted from the request path.

### Chain shape

- **One `SecurityFilterChain` `@Bean` per surface** (this slice introduces the API surface; the webapp surface follows the same shape and is deferred — see Scope).
- The chain's `securityMatcher` is an `OrRequestMatcher` of `PathPatternRequestMatcher` entries of the form `/physical-tenants/{id}/**`, **one entry per configured tenant id**, built at chain construction from `CamundaSecurityLibraryProperties.getPhysicalTenants()`. Requests under `/physical-tenants/{unknownId}/**` do not match the per-tenant chain at all and fall through to the existing catch-all deny in `BaseSecurityConfiguration` — surfacing as a 404, consistent with every other unhandled path.
- The chain delegates JWT validation to a custom `AuthenticationManagerResolver<HttpServletRequest>` that:
  1. Extracts the tenant id from the path segment following `/physical-tenants/`.
  2. Looks up a per-tenant `AuthenticationManager` from a `Map<String, AuthenticationManager>` materialised once at chain construction from the configured tenants and their `OidcConfiguration` blocks.
- Tenant ids are validated against `[a-zA-Z0-9_-]+` at properties-binding time. This guards against both regex injection in the matcher construction and ambiguity in path parsing.

### Order band

`CamundaSecurityFilterChainConstants` is renumbered to insert the new per-tenant band:

| Constant | Old | New |
|---|---|---|
| `ORDER_UNPROTECTED` | 0 | 0 |
| `ORDER_PHYSICAL_TENANT_WEBAPP_API` | — | 1 |
| `ORDER_WEBAPP_API` | 1 | 2 |
| `ORDER_UNHANDLED` | 2 | 3 |

These constants are package-private — they are not part of the consumer-facing surface guarded by [#198](https://github.com/camunda/camunda-security-library/issues/198). The renumbering is safe and does not require an override on the compatibility check.

The per-tenant chain outranking the top-level chain is defensive rather than required for correctness: top-level matchers (`pathPort.apiPaths()`, etc.) do not include `/physical-tenants/...` today, so the two are naturally disjoint. The explicit ordering makes that invariant visible in the code rather than load-bearing on tacit knowledge.

### Configuration shape

A new public configuration type is introduced in [`api/model/config/`](https://github.com/camunda/camunda-security-library/tree/main/api/src/main/java/io/camunda/security/api/model/config):

```java
public class PhysicalTenantConfiguration {
  private String id;
  private OidcConfiguration oidc = new OidcConfiguration();
  // future: BasicAuthConfiguration basic; SessionConfiguration session; etc.
}
```

It is a mutable class, not a record — `@ConfigurationProperties` list-binding requires setters, the same constraint that forced [`OidcConfiguration`](https://github.com/camunda/camunda-security-library/blob/main/api/src/main/java/io/camunda/security/api/model/config/OidcConfiguration.java) to be a class.

The type composes `OidcConfiguration` rather than redeclaring its 13 fields. Per-tenant config is the same IDP profile shape, scoped to one tenant. Adopters who already understand `OidcConfiguration` learn nothing new.

`CamundaSecurityLibraryProperties` binds the list at `camunda.security.physical-tenants[]`. The top-level `OidcConfiguration` slot at `camunda.security.authentication.oidc.*` is **not** deprecated, moved, or replaced — it remains the authoritative default IDP profile and continues to feed the existing top-level chains. Per-tenant entries are strictly additive.

```yaml
camunda:
  security:
    authentication:
      method: oidc                 # deployment-wide
      oidc:                        # top-level / default profile (unchanged)
        issuer-uri: https://default.example/idp
        audiences: [default-api]
    physical-tenants:              # per-tenant profiles (new)
      - id: acme
        oidc:
          issuer-uri: https://acme.example/idp
          audiences: [acme-api]
      - id: globex
        oidc:
          issuer-uri: https://globex.example/idp
          audiences: [globex-api]
```

### Method uniformity across tenants

A single deployment uses one authentication method, deployment-wide. `camunda.security.authentication.method` remains the single switch. `PhysicalTenantConfiguration` does **not** expose a per-tenant `method` field. Mixed-method deployments (some tenants on OIDC, others on basic) are out of scope and have no configuration affordance.

If a future product constraint introduces method-per-tenant, that is a separate decision and a separate ADR; the shape of `PhysicalTenantConfiguration` is forward-compatible with the addition of a sibling `basic` config slot.

### Static configuration only

The set of tenants and their settings is bound from `camunda.security.physical-tenants[]` once at Spring context refresh. The per-tenant `securityMatcher`, `AuthenticationManagerResolver`, and `JwtDecoder` map are materialised at chain construction and not mutated afterwards. Tenants cannot be added, removed, or reconfigured at runtime without a context restart.

This is "static" in the configuration sense — *resolving* the tenant id from the URL on every request is normal request handling, not dynamic configuration. Dynamic configuration (a runtime port that resolves tenant config per request) is deferred — see Out of Scope.

### Existing chain classes are not modified

`OidcWebappSecurityConfiguration`, `BasicAuthWebappSecurityConfiguration`, `OidcApiSecurityConfiguration`, `BasicAuthApiSecurityConfiguration`, `UnprotectedApiSecurityConfiguration`, and `BaseSecurityConfiguration` are not modified by this ADR. Their `securityMatcher`s do not match `/physical-tenants/{id}/...`; the new per-tenant chain handles those paths.

A deployment that does not opt in by `@Import`ing `PhysicalTenantOidcApiSecurityConfiguration` sees no chain-shape change from this ADR. How requests that lack a `/physical-tenants/` prefix are routed in Multi-Engine deployments is the subject of [ADR-0012](0012-default-tenant-rewrite-and-implicit-default-tenant.md).

### Hydration deferred

The work to propagate `physicalTenantId` into `CamundaAuthentication` and the hydration ports (`AuthorizationRepositoryPort`, the `CamundaAuthenticationConverter` family) is **deliberately out of scope** for this slice. The decision on *how* to propagate that context — new field on `CamundaAuthentication`, sibling context record, or request-scoped holder — is reserved for a follow-up ADR with its own POC. Locking that choice now, before the chain-split is exercised, would be premature.

### Scope of this slice

In scope:

- Configuration record `PhysicalTenantConfiguration` and its binding under `camunda.security.physical-tenants[]`.
- New `@Configuration` class `PhysicalTenantOidcApiSecurityConfiguration` carrying the `SecurityFilterChain` `@Bean`, registered at `@Order(ORDER_PHYSICAL_TENANT_WEBAPP_API)`.
- The `AuthenticationManagerResolver<HttpServletRequest>` and the per-tenant `JwtDecoder` materialisation.
- Renumbering of the package-private order constants.
- An integration test (`PhysicalTenantFilterChainIntegrationTest`) that asserts top-level + per-tenant + unknown-tenant deny via MockMvc, plus an `ApplicationContextRunner` assertion that the new bean is present only when tenants are configured.

Out of scope (each will warrant its own ADR if non-trivial):

- The webapp surface (`PhysicalTenantOidcWebappSecurityConfiguration`) and its `ClientRegistration`-per-tenant story.
- Basic-auth surface variants.
- Hydration-context propagation (the next POC).
- Dynamic tenant resolution and any outbound `TenantConfigurationPort`.
- Configurable path templates beyond `/physical-tenants/{tenantId}/**`.
- Per-tenant session cookie names, CSRF overrides, header overrides.

## Consequences

**Positive**

- The shape stays inside the patterns already adopted in `spring-boot-starter`: plain `@Bean` methods on `@Configuration` classes, `ObjectProvider` for customizers, explicit `@Import`-based activation per [ADR-0008](0008-no-spring-boot-auto-configuration.md). No new Spring discipline (e.g., `BeanDefinitionRegistryPostProcessor`) is introduced for a single use case.
- It is the idiomatic Spring Security pattern for multi-tenant resource servers. Reviewers reading the new chain code recognise an established pattern rather than a bespoke construction.
- Unknown-tenant failure mode (404) matches every other unhandled path on the server. There is no second failure-mode (401 from a deny-in-resolver) to reason about.
- The order band is explicit. The relative priority of per-tenant vs top-level vs unprotected vs catch-all is visible in `CamundaSecurityFilterChainConstants`, not implicit in the disjointness of matchers.
- The top-level configuration slot is untouched. Adopters do not learn a new config type; they learn that the type they already use can be repeated per tenant.
- `PhysicalTenantConfiguration` is forward-compatible with sibling slots for `basic`, `session`, `csrf`, and `httpHeaders` overrides, which will be needed by future slices and can be added additively without renaming or restructuring the existing fields.
- Deployments that don't enable physical tenants see no behaviour change. Roll-out is purely additive: a host imports the new configuration class when it's ready.

**Negative / accepted trade-offs**

- The mental model of "one chain per tenant" — implied by the language in [#200](https://github.com/camunda/camunda-security-library/issues/200) before this decision was made — is replaced by "one chain per surface, multi-tenant inside". The original framing has been corrected in the issue; future readers must learn that "split by physical tenant" means selection-within-a-chain, not chain-per-tenant.
- The `securityMatcher` must be rebuilt when the tenant set changes. Because the set is static, this means at context refresh only — but it imposes a hard floor on the dynamic-config feature: any future dynamic-tenant work will have to either rebuild the chain (acceptable but blunt) or move the matcher logic out of `securityMatcher` and into the resolver.
- One chain handling all configured tenants means the chain's customizers, filters, and configurers are shared across tenants. Per-tenant variation lives below the `AuthenticationManager` boundary. A tenant that needs (say) a different `SessionCreationPolicy` cannot get one without splitting the chain. This is accepted as a non-goal for the foreseeable future.
- The defensive `@Order` renumbering shifts two package-private constants. While safe (constants are package-private), it touches every existing chain configuration file and is verifiable only by recompilation and test runs.
- The decision to keep the existing top-level `OidcConfiguration` slot at `camunda.security.authentication.oidc.*` rather than fold everything into a uniform `physical-tenants` list means two configuration paths for OIDC profiles for the life of the project. This is judged less disruptive than a configuration migration that would force every existing adopter to rewrite their YAML.

## Alternatives Considered

- **N `SecurityFilterChain` beans, one per `(tenant, surface)`, via `BeanDefinitionRegistryPostProcessor`.** Rejected — would import a Spring registration pattern with no precedent in `spring-boot-starter` purely to satisfy the "chain per tenant" framing. The Spring-idiomatic pattern (`AuthenticationManagerResolver`) achieves the same isolation properties without introducing the new discipline.
- **`@Bean` method returning `List<SecurityFilterChain>`.** Rejected on technical grounds — Spring registers the list as a single bean of type `List`; `FilterChainProxy` does not unpack the elements into individual filter chains. The pattern does not work even setting aside style.
- **`ImportBeanDefinitionRegistrar` driven by a new `@EnablePhysicalTenants` annotation.** Rejected — introduces a public annotation that duplicates the existing `@Import`-based activation model from [ADR-0008](0008-no-spring-boot-auto-configuration.md). Adopters already opt in by importing a configuration class; a second switch adds surface area without removing any.
- **Broad `securityMatcher("/physical-tenants/*/**")` with a deny-everything `AuthenticationManager` returned by the resolver for unknown tenants.** Rejected — semantically muddier. An unknown tenant is an unknown route, not an authentication failure; surfacing it as 401 differs from how every other unconfigured path on the server behaves (404 via the catch-all). The narrow-matcher approach gives the same failure mode and leaves the resolver branch-free.
- **Per-tenant `method` field on `PhysicalTenantConfiguration`.** Rejected — the product constraint is method-uniformity across a deployment. Adding the field would imply mixed-method deployments are supported, which they are not. Adding it later (additively) is straightforward if the constraint changes.
- **Use `JwtIssuerAuthenticationManagerResolver` keyed by JWT `iss` claim rather than a custom path-keyed resolver.** Rejected — would mean that any token issued by the acme IDP is accepted at `/physical-tenants/globex/**` (and vice versa) because the resolver keys off the token, not the path. The path-keyed resolver enforces tenant–path binding by construction: the path decides which decoder runs; mismatched tokens fail decode.
