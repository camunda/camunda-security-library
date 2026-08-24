---
status: Accepted
---

# ADR-0014: OIDC UserInfo — the login-time `userInfoEnabled` toggle and request-time claim augmentation

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

[ADR-0008](0008-no-spring-boot-auto-configuration.md) centralised the OIDC webapp filter chain in CSL, which brought two independent UserInfo-endpoint concerns into the library at once:

1. **Login-time fetch.** By default, Spring Security's `oauth2Login` DSL fetches the IdP's UserInfo endpoint after token exchange and merges the returned claims into the `OidcUser`. The `ClientRegistration` carries the UserInfo URL — either populated by OIDC discovery when `issuer-uri` is set, or by the explicit `user-info-uri` property when discovery is not used. Some IdPs do not implement `/userinfo` at all, or return claims the host does not want surfaced; the camunda monorepo has long-standing deployments that actively disable the fetch (see [`OidcAuthenticationConfiguration.userInfoEnabled`](https://github.com/camunda/camunda/blob/main/security/security-core/src/main/java/io/camunda/security/configuration/OidcAuthenticationConfiguration.java)), and losing that toggle on OC's adoption of the CSL chain (camunda#52121) would regress those deployments. The `OidcUserService` extension hook in [`OidcWebappSecurityConfiguration`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/OidcWebappSecurityConfiguration.java) is the existing escape valve, but it is all-or-nothing — a host has to hand-roll an entire `OidcUserService` just to skip the fetch.
2. **Request-time augmentation.** OIDC access tokens are size-constrained; IdPs often omit authorization-relevant claims (groups, roles, custom attributes) from the token to keep it compact. The workaround is to call the IdP's `/userinfo` endpoint at request time — independent of login — and merge the additional claims into the claims map used for authorization decisions. The camunda monorepo already ships this behaviour in `CachingOidcClaimsProvider` / `OidcUserInfoAugmentationConfiguration`; until CSL owns it, Orchestration Cluster adoption via #38 cannot replace the monorepo's auth wiring without regressing this capability. Three invariants must hold regardless of implementation: the access token's JWT claims (cryptographically signed) must never be overrideable by an unsigned UserInfo response; a degraded `/userinfo` endpoint must not block authentication (fail-open); and a failing IdP must not be hammered with retries on every request (negative caching).

[ADR-0013](0013-multi-idp-oidc-configuration.md) makes OIDC configuration additive across the flat block and `providers.oidc.<id>.*`. Since each entry binds to the same `OidcConfiguration` type, both concerns above become per-provider automatically once expressed as fields on that type.

These two concerns interact: the augmentation path derives its per-issuer UserInfo URI from the same `ClientRegistration` the login-time toggle controls. The core question this ADR answers:

> What property shape and wiring let CSL expose both an independent login-time UserInfo-fetch toggle and an opt-in request-time claim-augmentation layer, per IdP in a multi-provider setup, while making the coupling between the two mechanisms explicit rather than a trap a host discovers in production?

## Decision

### `userInfoEnabled` — the login-time fetch toggle

CSL exposes a boolean `userInfoEnabled` property on `OidcConfiguration`, defaulting to `true`, applied by nulling `userInfoUri` when the flag is false. The name, default, and application mechanism mirror the monorepo's [`ClientRegistrationFactory`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/ClientRegistrationFactory.java) so OC adoption is a drop-in.

```yaml
camunda:
  security:
    authentication:
      # Flat (single-IdP):
      oidc:
        user-info-enabled: true   # default

      # Per-provider (multi-IdP), under the additive ADR-0013 shape:
      providers:
        oidc:
          keycloak:
            user-info-enabled: true
          azure:
            user-info-enabled: false
```

`userInfoEnabled` lives on `OidcConfiguration`. Because both the flat block and each `providers.oidc.<id>` entry bind to that type, the flag is per-provider by construction — no additional plumbing needed.

`ScopedClientRegistrationFactory#buildClientRegistration` builds each `ClientRegistration` from its `OidcConfiguration` — the single shared factory behind both the cluster-wide `ClientRegistrationRepository` (`OidcBeansConfiguration`) and any per-scope chain. After applying the standard fields, it calls `builder.userInfoUri(null)` when `oidc.isUserInfoEnabled()` returns false. This runs after the registration builder is obtained from either of the two upstream branches — discovery via `ClientRegistrations.fromIssuerLocation` when `issuer-uri` is set, or `ClientRegistration.withRegistrationId(...)` with explicit endpoints when it is not — so the toggle behaves identically regardless of how the URI was obtained, and applies uniformly to every scope, not only the global registration.

The `oauth2Login` DSL is untouched. When the registration has no `userInfoUri`, Spring Security skips the UserInfo step entirely; when it has one, the default flow runs.

A host bean registered against `OidcUserService` continues to take precedence over the library default. The toggle and the bean are independent levers:

| `userInfoEnabled` | Host `OidcUserService` | Result |
|---|---|---|
| `true` (default) | absent | Library default `OidcUserService` runs, fetches UserInfo |
| `true` | present | Host `OidcUserService` runs (may or may not fetch) |
| `false` | absent | No UserInfo call — `userInfoUri` is null on the registration |
| `false` | present | Host `OidcUserService` runs against a registration with no `userInfoUri`; host code can still fetch from any URL it chooses |

The library does not try to second-guess the host. A host that registers its own `OidcUserService` is in full control; the toggle only governs the library's default wiring.

### Request-time claim augmentation

An opt-in `CachingOidcClaimsProvider` sits in the CSL OIDC chain, independent of login:

- **Disabled by default.** Augmentation is off unless `camunda.security.authentication.oidc.user-info-augmentation.enabled=true`. When disabled, a `NoopOidcClaimsProvider` pass-through is registered.
- **JWT-wins merge.** The UserInfo claims map is seeded first; `putAll` of the JWT claims then overwrites every conflicting key — a single expression that mechanically enforces the trust-boundary invariant, with no per-claim allowlist to maintain.
- **Fail-open.** Any exception in the fetch path (network, non-2xx HTTP status, JSON parse error, OIDC §5.3.2 `sub` mismatch) is caught, logged at ERROR with the issuer and error message, and the JWT claims are returned unchanged. A negative-cache entry is stored immediately to prevent retry storms.
- **Negative caching.** Failed fetches store a sentinel-marked entry that expires after `negativeCacheTtl` (default 5 s); within that window subsequent requests for the same token skip the fetch entirely. (Successful fetches share the same cache under a longer default TTL — 5 minutes, capped at 10,000 entries — so this is one cache serving both outcomes, not two.)
- **Cache key: `iss+jti`, falling back to `iss+sub+iat+exp`.** No bearer-token material is held in cache-key space. The `iss` prefix is required because RFC 7519 §4.1.7 only mandates per-issuer uniqueness for `jti`; two providers can legitimately issue tokens with identical `jti` values. When `jti` is absent, the fallback uses `sub+iat+exp`; when neither key is constructable the cache is bypassed for that request (rare — every mainstream IdP emits at least `sub+iat+exp`).
- **Per-issuer routing.** The provider builds an `issuer → userInfoUri` map from `ClientRegistration`s at construction time. Each call's JWT `iss` claim selects the target URL. An issuer with no entry in the map is fail-open at DEBUG (not WARN, to avoid log spam on every request) — the JWT claims are returned unaugmented. This dovetails with the multi-IdP shape from [ADR-0013](0013-multi-idp-oidc-configuration.md).
- **HTTP client.** `java.net.http.HttpClient` (JDK built-in, no extra dependency), wrapped behind a package-private fetcher interface so unit tests can inject a mock without spawning a real HTTP server.
- **Micrometer metrics (optional).** `camunda.oidc.userinfo.cache` (Counter; `issuer`, `result`: hit/miss/negative_hit) and `camunda.oidc.userinfo.fetch` (Timer; `issuer`, `outcome`: success/failure). Metric names match the monorepo reference; tag shapes intentionally diverge to carry more context than the monorepo's untagged/partially-tagged equivalents — a required Micrometer dependency, but the provider runs uninstrumented when no `MeterRegistry` bean is present (the constructor accepts a nullable one).
- **Bean wiring.** `OidcClaimsProviderConfiguration` is a plain `@Configuration` activated when `camunda.security.authentication.method=oidc`; the caching bean carries `@ConditionalOnProperty(enabled=true)` and the noop carries the mutually exclusive `@ConditionalOnProperty(enabled=false, matchIfMissing=true)`, both additionally gated `@ConditionalOnMissingBean` so registration is deterministic regardless of declaration order and a host-supplied `OidcClaimsProvider` bean suppresses both. **`ScopedOidcClaimsProviderFactory` (`spring-boot-starter/.../oidc/ScopedOidcClaimsProviderFactory.java`) provides the same construction per arbitrary per-scope `AuthenticationConfiguration`**, reading the augmentation flag and cache settings from that scope's own config rather than the global properties — so per-provider/per-scope augmentation configuration already exists today, not deferred to future scaffolding.

### The coupling between the two mechanisms, stated plainly

Both mechanisms read the same `ClientRegistration.getProviderDetails().getUserInfoEndpoint()`, so `userInfoEnabled=false` reaches into augmentation even though the two properties are unrelated on their face. The actual effect depends on how many configured providers have the fetch disabled:

- **All providers disabled (or none configured) for a given scope, augmentation enabled for that scope.** The issuer→userInfoUri map used to build the claims provider is empty, and `CachingOidcClaimsProvider.forConfiguredMappings` **fails fast with an `IllegalStateException`** at provider-construction time — a Spring context startup failure for the cluster-wide default, or a scope-construction failure for a per-scope config. This is a deliberate config-mismatch guard: augmentation enabled with nothing to ever augment must surface loudly, not run silently doing nothing.
- **Only some providers in a multi-IdP deployment have the fetch disabled.** The map still has entries for the providers with `userInfoEnabled=true`, so construction succeeds. A bearer token whose `iss` matches one of the *disabled* providers hits the same "issuer not in the map" path as an unrecognised issuer: `claimsFor` logs at DEBUG and returns the JWT claims unaugmented, with no error surfaced anywhere. This is the case where the coupling is genuinely silent — a host running multiple IdPs with per-provider `userInfoEnabled` toggles can end up with augmentation quietly inert for exactly the providers it disabled the login-time fetch on.

In both cases, the interaction is a consequence of one design choice — nulling `userInfoUri` at the source rather than gating the `oauth2Login` DSL specifically — which is exactly why that choice keeps every downstream reader of `ProviderDetails.userInfoEndpoint` honest instead of leaving a URL on the registration that augmentation would wrongly trust as reachable.

### Why these particular boundaries

- **Boolean, not URL, for the login-time toggle.** The URL is already first-class on `OidcConfiguration` (`userInfoUri`) and populated by discovery when `issuer-uri` is set. The decision worth surfacing to operators is "should we call it?", not "what is its address?" — mirrors the monorepo.
- **Apply the toggle post-build by nulling `userInfoUri` on the registration, not by gating `oauth2Login`'s `userInfoEndpoint(...)`.** Gating the DSL would only cover the webapp login flow and would leave the URL visible on the registration for any other reader — notably the augmentation layer above, which derives its per-issuer map from that same field. Nulling at the source keeps every consumer honest and matches the monorepo's `ClientRegistrationFactory`.
- **Default `true` for the toggle.** Matches Spring Security's out-of-the-box behaviour and the monorepo's default; disabling fetch is the opt-in for hosts that need it.
- **Per-provider by construction, no global override, for both mechanisms.** Both fields live on `OidcConfiguration`, so the additive multi-IdP shape from ADR-0013 expresses per-provider toggles for free; a separate global override would add ambiguity without behavioural gain.
- **Augmentation disabled by default, fail-open, negative-cached.** Augmentation is an opt-in capability layered on top of a potentially-unreliable external call; defaulting it off means existing deployments are unaffected until they opt in, and the fail-open/negative-cache combination means a degraded `/userinfo` degrades augmentation, not authentication.
- **Fail fast on a provider-construction-time config mismatch, fail open on a request-time fetch failure.** These are different failure classes: an augmentation config that can never augment anything is a deployment mistake the operator needs to see immediately, while a transient `/userinfo` outage is an expected operational condition the auth chain must tolerate. Conflating them — either failing open on both, or failing the request on both — would hide the mistake in the first case or take down authentication in the second.

### Default implementations and override boundaries

| Concern | Default | Override path |
|---|---|---|
| `userInfoEnabled` | `true` (per-provider) | Set `camunda.security.authentication.oidc.user-info-enabled` or `providers.oidc.<id>.user-info-enabled` to `false` |
| Spring's default `OidcUserService` | Library-supplied via `oauth2Login` | Host registers `@Bean OidcUserService` — takes precedence regardless of the toggle |
| UserInfo URL source | Discovery (when `issuer-uri` is set) or explicit `user-info-uri` | Property `user-info-uri` overrides the discovered value |
| `OidcClaimsProvider` | `NoopOidcClaimsProvider` unless `user-info-augmentation.enabled=true`, then `CachingOidcClaimsProvider` | Host registers `@Bean OidcClaimsProvider`; suppresses both CSL defaults |
| Per-scope claims provider | `ScopedOidcClaimsProviderFactory#buildClaimsProvider`, reading the scope's own `AuthenticationConfiguration` | Host supplies its own factory/provider for that scope |

## Consequences

**Positive**

- OC adoption (camunda#52121, #38) preserves customer deployments that disable UserInfo fetch today and those that rely on the monorepo's claim-augmentation cache, with no code change and only a property-path migration.
- Both mechanisms are per-provider with no new code paths, falling out of the additive ADR-0013 shape and the already-existing `ScopedOidcClaimsProviderFactory` — a multi-IdP, multi-scope deployment can mix fetch-enabled/disabled and augmentation-enabled/disabled per provider today.
- The login-time toggle composes with the existing `OidcUserService` SPI rather than competing with it; hosts needing finer control still register their own bean, hosts that only need on/off get a property.
- Augmentation degrades gracefully under IdP failure: the first failure adds a negative-cache entry, retries are suppressed for `negativeCacheTtl`, and authentication continues throughout.
- The coupling between the two mechanisms is a stated, tested behaviour (config-mismatch fail-fast in one shape, silent per-issuer no-op in the other) rather than an undocumented trap a host discovers via a support ticket.

**Negative / accepted trade-offs**

- Nulling `userInfoUri` on the built `ClientRegistration` loses the discovered URL even though the host configured `issuer-uri`. Re-enabling fetch at runtime without a restart would need to refresh the registration; accepted as a non-goal nobody has asked for.
- A host running a multi-IdP deployment with per-provider `userInfoEnabled` toggles can end up with augmentation silently inert for exactly the providers it disabled the fetch on, with no error surfaced. Accepted because the alternative — erroring per-request on a legitimately-configured "this provider doesn't support/want UserInfo" choice — would be worse than the current DEBUG-logged pass-through, and because the all-providers-disabled case (the more likely operator mistake) does fail fast.
- Micrometer's required-dependency-but-optional-`MeterRegistry` shape means the augmentation layer always carries the dependency even for hosts that never enable augmentation; accepted as the cost of one shared bean shape.
- Per-scope augmentation configuration reads from that scope's own `AuthenticationConfiguration`, not the cluster's global properties — a host that expects scope-level augmentation to inherit the cluster default must configure each scope explicitly.

## Alternatives Considered

- **Gate the `oauth2Login` DSL via `userInfoEndpoint(...)` instead of nulling `userInfoUri` on the registration.** Rejected — leaves the URL visible on the registration, so the augmentation layer (which reads `ProviderDetails.userInfoEndpoint` directly) would incorrectly conclude UserInfo is reachable for a provider the host explicitly disabled it for. Nulling at the source keeps every consumer honest and matches the monorepo.
- **On a provider-construction-time config mismatch (augmentation enabled, no provider yields a URI), fail open instead of fail fast.** Rejected — an operator who enables augmentation and gets no error, yet also gets no augmented claims, has no signal anything is wrong. A loud `IllegalStateException` at startup (or scope construction) is cheaper to diagnose than a silently-inert feature discovered much later.

Consolidates records previously numbered 0026 (see git history).
