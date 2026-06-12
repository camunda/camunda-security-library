---
status: Accepted
---

# ADR-0026: UserInfo claim augmentation

**Deciders**: <!-- fill in before merging -->

## Status

Accepted

## Context

OIDC access tokens are size-constrained: IdPs often omit authorization-relevant
claims (groups, roles, custom attributes) from the token to keep it compact.
The workaround is to call the IdP's `/userinfo` endpoint at request time and
merge the additional claims into the claims map used for authorization decisions.

The camunda monorepo already ships this behaviour in
`CachingOidcClaimsProvider` / `OidcUserInfoAugmentationConfiguration`. Until
CSL owns it, Orchestration Cluster adoption via #38 cannot replace the
monorepo's auth wiring without regressing this capability.

Three design invariants must hold regardless of implementation:

1. **JWT trust boundary.** The access token is cryptographically signed by the
   IdP. Claims in the JWT must never be overrideable by an unsigned UserInfo
   response. Allowing UserInfo to override `sub`, `iss`, or `exp` would let a
   compromised UserInfo endpoint undermine the token's security guarantees.

2. **Fail-open.** A degraded `/userinfo` endpoint must not block authentication.
   The auth chain must continue with JWT-only claims on any fetch failure.

3. **Retry dampening.** A failing IdP must not be hammered with retries on every
   request. Negative caching limits the blast radius of an outage.

## Decision

Add an opt-in `CachingOidcClaimsProvider` to the CSL OIDC chain:

- **Disabled by default.** Augmentation is off unless
  `camunda.security.authentication.oidc.user-info-augmentation.enabled=true`.
  When disabled, a `NoopOidcClaimsProvider` pass-through is registered.

- **JWT-wins merge.** The UserInfo claims map is seeded first; then `putAll` of
  the JWT claims overwrites every conflicting key. This is a single expression
  that mechanically enforces the invariant — no per-claim allowlist to maintain.

- **Fail-open.** Any exception in the fetch path (network, non-2xx HTTP status,
  JSON parse error, OIDC §5.3.2 `sub` mismatch) is caught, logged at ERROR with
  the issuer and error message, and the JWT claims are returned unchanged. A
  negative cache entry is stored immediately to prevent retry storms.

- **Negative caching.** Failed fetches store a sentinel-marked entry that
  expires after `negativeCacheTtl` (default 5 s). Within that window subsequent
  requests for the same token skip the fetch entirely. This bounds retry
  frequency during IdP outages without silently dropping augmentation forever.

- **Cache key: raw token value.** The Caffeine cache is keyed by the bearer
  token string. Tokens rotate on refresh; the 5-minute default `cacheTtl` is
  short enough that stale claims are not a concern. Keying by `(iss, sub)` would
  survive refreshes but would hold claims longer — trading resilience for the
  risk of serving stale group memberships after a user's roles change in the IdP.
  Token-value keying matches the monorepo reference and is the safer default.

- **Per-issuer routing.** The provider builds an `issuer → userInfoUri` map from
  `ClientRegistration`s at startup. On each call the JWT's `iss` claim selects
  the target URL. An unknown issuer is treated as fail-open (DEBUG log, JWT
  claims returned; WARN would spam logs on every request). This dovetails with the multi-IdP configuration shape
  introduced in ADR-0013.

- **HTTP client.** `java.net.http.HttpClient` (JDK built-in, no extra dep).
  Wrapped behind a package-private `OidcUserInfoFetcher` interface so unit tests
  can inject a mock without spawning a real HTTP server.

- **Micrometer metrics (optional).** Two instruments, metric names matching the
  monorepo so existing dashboards carry over:
  - `camunda.oidc.userinfo.cache` (Counter, tags: `issuer`, `result`: hit /
    miss / negative_hit)
  - `camunda.oidc.userinfo.fetch` (Timer, tags: `issuer`, `outcome`: success /
    failure)
  Micrometer is a required dependency of the starter; if no `MeterRegistry` bean is
  present in the application context the provider functions without instrumentation
  (the constructor accepts a nullable `MeterRegistry`).

- **Bean wiring.** `OidcClaimsProviderConfiguration` is a plain `@Configuration`
  activated by `camunda.security.authentication.method=oidc`. It declares the
  caching bean first (guarded by `@ConditionalOnProperty` for `enabled=true`)
  and the noop second (guarded only by `@ConditionalOnMissingBean`). Declaration
  order ensures that when the caching bean registers, the noop backs off; when
  the property is absent, the noop registers. A host-supplied
  `OidcClaimsProvider` bean suppresses both.

## Relationship to ADR-0014 / #156

ADR-0014's `userInfoEnabled` toggle controls whether the `ClientRegistration`
built by `OidcBeansConfiguration` includes a `userInfoUri` at all — i.e.
whether Spring Security calls UserInfo during the *webapp login* flow. This
ADR's augmentation is orthogonal: it operates at *request time* on bearer-token
authentication, not at login time. The two settings are independent; enabling
augmentation does not require `userInfoEnabled=true`, but both features require
the IdP's `/userinfo` endpoint to be reachable.

## Consequences

- Hosts that set `user-info-augmentation.enabled=true` get claims from UserInfo
  merged into every authenticated request's claims map, at the cost of one
  (cached) HTTP call per unique token value.
- A failing `/userinfo` degrades gracefully: the first failure adds a negative
  entry; retries are suppressed for `negativeCacheTtl`; authentication continues
  throughout.
- The `NoopOidcClaimsProvider` default means existing deployments are unaffected
  until they opt in.
- Per-provider configuration (one augmentation config per IdP) is deferred until
  the providers scaffolding in #74 lands.
