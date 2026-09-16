---
status: Accepted
---

# ADR-0006: Additive multi-IdP OIDC configuration with an issuer-aware `JwtDecoder`

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

CSL owns the OIDC webapp and API filter chains ([ADR-0003](0003-no-spring-boot-auto-configuration.md)), so it also owns the `ClientRegistrationRepository` those chains route logins through and the resource-server `JwtDecoder` they validate bearer tokens with. Spring Security's `OAuth2LoginAuthenticationFilter` routes login attempts per provider via `/oauth2/authorization/{registrationId}` URLs, so multi-IdP *login* works out of the box once multiple `ClientRegistration` instances exist. Multi-IdP *token validation* does not — that is a decoder concern.

Orchestration Cluster (OC) already supports multiple IdPs. [`AuthenticationConfiguration#getProviders()`](https://github.com/camunda/camunda/blob/main/security/security-core/src/main/java/io/camunda/security/configuration/AuthenticationConfiguration.java) returns a [`ProvidersConfiguration`](https://github.com/camunda/camunda/blob/main/security/security-core/src/main/java/io/camunda/security/configuration/ProvidersConfiguration.java) carrying `Map<String, OidcAuthenticationConfiguration>`, and OC's [`OidcAuthenticationConfigurationRepository`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/OidcAuthenticationConfigurationRepository.java) merges that map with the flat `oidc.*` block: flat contributes a registration when `clientId` is non-blank, and the providers map is then applied on top via `Map#putAll`, so a colliding provider id overwrites the flat entry. Separately, OC validates tokens through `OidcAccessTokenDecoderFactory`, `JWSKeySelectorFactory`, `IssuerAwareJWSKeySelector` and a small composite JWK source. Any OC deployment running with multiple configured IdPs — or with signing keys published across more than one JWK Set endpoint — regresses on cutover to the CSL chains unless CSL ships equivalent behaviour.

Two intermediate states in CSL's own history shaped this record. An earlier iteration built the multi-`ClientRegistration` aggregation but declined to build a decoder across more than one provider, failing startup with an `IllegalStateException` and telling the host to pin a flat block or register its own `@Bean JwtDecoder`; that refusal was the direct blocker on OC adoption. And `camunda.security.authentication.oidc.additional-jwk-set-uris` existed on the config surface but was inert — adopters who set it saw every validation request still go to the single `jwk-set-uri`.

The core question this ADR answers:

> What property shape, merge semantics, and decoder-construction rules let CSL preserve OC's multi-IdP and multi-JWKS behaviour exactly, keep single-IdP adopters working unchanged, and validate tokens from every configured provider without the host registering an override?

## Decision

### Property shape

Two complementary shapes combine additively at startup, mirroring OC's repository. Hosts use either or both.

- **Flat** — `camunda.security.authentication.oidc.*`. Binds to an `OidcConfiguration` on `AuthenticationConfiguration#getOidc()`. The single-IdP path works with no property migration.
- **Providers** — `camunda.security.authentication.providers.oidc.<id>.*`. Binds to `Map<String, OidcConfiguration>` on `AuthenticationConfiguration#getProviders().getOidc()`. The intermediate `oidc` segment exists so the `providers` block can host other provider families (basic, SAML) later without a schema change.

Both `OidcProvidersConfiguration#setOidc` and `AuthenticationConfiguration#setProviders`/`setOidc` normalise null to a fresh empty instance, so a YAML `~` binding cannot reintroduce NPEs in downstream iteration.

### Merge into one provider map, then into `ClientRegistrationRepository`

The two shapes are flattened into a single `LinkedHashMap<String, OidcConfiguration>` keyed by registration id, applying in order:

1. If the flat block's `clientId` is non-blank, put the flat block under its `registrationId` (default `oidc`).
2. `putAll(providers.oidc)` — a colliding provider id overwrites the flat entry.

That merged map is the library's single source of provider configuration; it is exposed to the rest of the library through the `OidcProviderConfigurationPort` inbound port so every consumer (decoder, authorization-request resolver, claims provider, per-scope chains) reads the same view. Each entry is built into a `ClientRegistration` by a shared factory: discovery via `issuer-uri` when set, with explicit `authorization-uri`/`token-uri`/`jwk-set-uri`/`user-info-uri` overrides layered on top to plug gaps in incomplete IdP discovery metadata. Blank `registrationId` values fail fast with an exception naming the misconfigured property; blank URI values are treated as missing via `StringUtils.hasText` so empty environment-variable bindings do not slip through to a generic Spring assertion. The result is wrapped in an `InMemoryClientRegistrationRepository`. An empty merged map fails with an `IllegalStateException` pointing the adopter at both property shapes.

### Decoder selection: a registration-count switch

The library builds exactly one `JwtDecoder` bean. Which decoder it builds is decided by counting registrations, not by reading properties:

- **1 registration** (flat block, or a single `providers.oidc.<id>` entry) — a single-issuer `NimbusJwtDecoder`. Behaviour is unchanged from the single-IdP releases; there is no regression for single-IdP hosts.
- **more than 1 registration** (several `providers.oidc.*` entries, with or without a flat block) — an issuer-aware decoder built from `IssuerAwareJWSKeySelector` and `IssuerAwareTokenValidator`. The decoder reads the token's `iss` claim and routes key selection *and* validation to the matching registration.

Every registration on the issuer-aware path must carry an `issuer-uri`; the count switch validates this before building and fails with `IllegalArgumentException` — `"The following OIDC Providers are missing 'issuerUri': <ids>"` — naming the offending registration ids. A token whose `iss` matches no configured provider fails with a `BadJwtException` whose message is `"Unknown issuer '<iss>'. No matching client registration found."`, so the offending issuer is visible in the 401 diagnosis rather than buried.

Every registration must also resolve a JWK Set URI — set explicitly via `jwk-set-uri`, or populated by OIDC discovery from `issuer-uri`. A registration that resolves neither fails with `IllegalArgumentException` naming the provider and its issuer URI.

The switch reads the registrations out of `ClientRegistrationRepository`, which therefore has to implement `Iterable<ClientRegistration>`. The library default, `InMemoryClientRegistrationRepository`, does. A host wiring a custom non-iterable repository gets an `IllegalStateException` naming that requirement and must register its own `@Bean JwtDecoder`.

### `additional-jwk-set-uris`: one composition mechanism, routed per issuer

`additional-jwk-set-uris` is a property of `OidcConfiguration`, so it is per-provider and applies in both modes. **Both modes compose additional URIs through the same mechanism** — a `CompositeJWKSource` behind a `JWSVerificationKeySelector`, built by `JWSKeySelectorFactory` from a provider's primary `jwk-set-uri` plus its additional URIs. What differs between the modes is *routing*, not whether composition happens:

- **More than one registration — per-issuer routing.** `IssuerAwareJWSKeySelector` keys key-selectors by issuer URI, creating each one lazily on first sighting of that `iss` and caching it in a `ConcurrentHashMap`. Each per-issuer selector is built from that registration's own `jwk-set-uri` and its own additional URIs, so a token from provider A is verified against A's primary and additional URIs only — the result is one `CompositeJWKSource` per issuer that has additional URIs configured. The per-issuer additional-URI map is derived from the merged provider map, keyed by issuer URI; only registrations with a non-blank `issuer-uri` and at least one non-blank additional URI contribute an entry.
- **Exactly one registration — no routing.** With a single issuer there is nothing to route by, so there is exactly one key selector, backed by exactly one `CompositeJWKSource` over that registration's primary and additional URIs.

In either mode, a provider that configures no additional URIs gets a plain single-URI `JWKSource` rather than a composite — the composite is introduced only where there is more than one URI to compose.

`CompositeJWKSource<C extends SecurityContext>` implements Nimbus's `JWKSource<C>` directly. `get(JWKSelector, C)` iterates the sources in declared order — primary `jwk-set-uri` first, then each additional URI as configured — and:

1. returns the first non-empty result;
2. on `KeySourceException`, logs a warning (distinguishing "trying next source" from "no further sources to try" on the final element) and continues to the next source;
3. propagates any other unchecked exception immediately — those are bugs, not network failures;
4. returns an empty list if every source returns empty without failing;
5. rethrows the last `KeySourceException` if every source failed, so the caller sees a meaningful message.

One Nimbus `JWKSource` is built per URI via `JWKSourceBuilder.create(url).refreshAheadCache(false).rateLimited(false).cache(true).build()` — the same settings Spring's `NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder` uses internally. The composite is plugged into a `JWSVerificationKeySelector`. This is the same code path in both modes; on the multi-provider path it simply runs once per issuer.

All decoder paths share one algorithm set — `RS256/384/512` plus `ES256/384/512` — so algorithm acceptance does not depend on which path the configuration happens to trigger. All paths likewise apply the same validator chain, including a `JwtIssuerValidator` whenever the provider's `issuer-uri` is set, so no path silently drops the `iss` check.

`OidcAccessTokenDecoderFactory` owns the count switch and the decoder assembly; `JWSKeySelectorFactory` owns key-selector construction (including the composite); `TokenValidatorFactory` owns validator construction. All three are library-supplied `@ConditionalOnMissingBean` beans and are independently overridable, as is `JwtDecoder` itself.

### Why these particular boundaries

- **Additive property shapes, not exclusive.** An earlier draft made the providers map *replace* the flat block when present and logged a deprecation warning. Rejected in review: OC's repository merges the two shapes, so adopters running OC with both blocks set would regress. Treating the flat block as one ordinary entry in the merged map keeps semantics identical and removes any need for deprecation messaging — the flat block is not deprecated, only narrower.
- **Mirror OC's collision rule (providers overwrite flat).** `Map#putAll` semantics are what the existing customer base relies on. Diverging — raising on collision, for example — would silently change behaviour for hosts migrating from OC.
- **`clientId` non-blank as the flat-block signal.** Matches OC. The alternative ("flat is configured if any URI is set") was rejected because a half-configured flat block should surface as an informative startup failure rather than being silently ignored.
- **`providers.oidc.<id>.*`, not `providers.<id>.*`.** Mirrors OC's `ProvidersConfiguration { Map<String, OidcAuthenticationConfiguration> oidc; }`. The extra segment leaves room for other provider families without a breaking schema change.
- **An issuer-aware *decoder*, not `JwtIssuerAuthenticationManagerResolver`.** Spring Security's resolver routes by `iss` at the filter level, producing a per-issuer `AuthenticationManager` wired into the filter-chain DSL. That is the wrong injection shape for CSL: the resource-server chain, `OidcUserAuthenticationConverter`, the per-scope chain builders and any host bean that injects `JwtDecoder` all expect a single `JwtDecoder` bean, so routing at the decoder keeps one injection point and leaves the chain configuration untouched. The resolver also requires discovery metadata for every issuer at startup, which conflicts with CSL's support for explicit endpoint URIs, and it offers no composition point for per-provider `additional-jwk-set-uris` — each issuer would need a hand-built resolver. Decoder-level routing additionally matches OC's existing `OidcAccessTokenDecoderFactory`, which is the behaviour being preserved.
- **A custom `CompositeJWKSource` over a Spring or Nimbus built-in.** `NimbusJwtDecoder.withJwkSetUri(uri)` accepts one URI and exposes no hook for replacing the underlying `JWKSource`; Nimbus's `JWKSourceBuilder` is single-URL only. The composite is ~40 lines wrapping a public Nimbus interface; the only alternative is a custom HTTP client that re-implements caching, which is far more code and risk.
- **Primary-first short-circuit, not key merging.** Querying sources in declared order with first-non-empty-wins keeps the `kid` collision policy unambiguous ("primary wins") and lets adopters re-order URIs to change precedence. Merging all keys before selection would force globally unique `kid` values across endpoints, which is operationally fragile during a rotation window. **Assumption:** tokens carry a `kid` header — standard practice for any deployment running more than one signing key. A `kid`-less token makes Nimbus's `JWKSelector` match *every* key in a JWK Set, so the composite short-circuits on the primary's keys and never consults the additional URIs. This matches the monorepo's selector. An adopter whose IdP issues `kid`-less tokens *and* relies on a secondary URI for signature verification must register a custom `@Bean JwtDecoder`.
- **Lazy failure on unreachable additional URIs, no eager startup probe.** Eager probing would block startup on each URI's network latency and give false confidence — a URI reachable at startup can go down five minutes later. The composite already degrades gracefully at runtime: a failing source logs WARN and the next is tried. Spring's and Nimbus's own JWK source paths are lazy; aligning with them keeps the operator failure model uniform.
- **One RSA + EC algorithm set everywhere.** This is a **deliberate behavioural change**, not a no-op: Spring's `NimbusJwtDecoder.withJwkSetUri(...).build()` defaults to RS256 only, so a single-URI deployment that relied on that default now also accepts EC algorithms. Three reasons override the cost. The monorepo's [`JWSKeySelectorFactory`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/JWSKeySelectorFactory.java) uses the wider set everywhere, so adopters relying on EC today would regress on adoption of the CSL chains. A host that adds `additional-jwk-set-uris` must not discover that the composite path quietly accepts EC tokens the single-URI path rejected — aligning every path removes that surprise. And RS256/384/512 + ES256/384/512 covers every algorithm a public-issuer IdP is likely to use; rejecting EC by default would be more surprising than accepting it. Hosts needing a narrower set register their own `@Bean JwtDecoder`.

### Default implementations and override boundaries

| Concern | Default | Override path |
|---|---|---|
| `ClientRegistrationRepository` | `InMemoryClientRegistrationRepository` populated from the merged flat + providers map | Host registers any `@Bean ClientRegistrationRepository` — the CSL default backs off via `@ConditionalOnMissingBean`. A non-iterable repository additionally requires a host `@Bean JwtDecoder` |
| `JwtDecoder`, 1 registration | Single-issuer `NimbusJwtDecoder` built from the registration's JWK Set URI | Host registers `@Bean JwtDecoder` |
| `JwtDecoder`, more than 1 registration | Issuer-aware decoder (`IssuerAwareJWSKeySelector` + `IssuerAwareTokenValidator`); every registration needs an `issuer-uri` | Host registers `@Bean JwtDecoder` |
| `additional-jwk-set-uris`, more than 1 registration | One `CompositeJWKSource` per issuer, behind a per-issuer `JWSVerificationKeySelector`, routed by `IssuerAwareJWSKeySelector` on the token's `iss` | Host registers `@Bean JWSKeySelectorFactory` or `@Bean JwtDecoder` |
| `additional-jwk-set-uris`, 1 registration | One `CompositeJWKSource` over primary + additional URIs, behind a `JWSVerificationKeySelector`; no routing layer | Same |
| A provider with no additional URIs (either mode) | Plain single-URI Nimbus `JWKSource` — no composite | Same |
| Accepted signature algorithms | `RS256/384/512` + `ES256/384/512`, uniform across all decoder paths | Host registers `@Bean JWSKeySelectorFactory` (or `@Bean JwtDecoder`) with a narrower set |
| Token validators (timestamp, audience, `iss`) | `TokenValidatorFactory`, adding `JwtIssuerValidator` when the provider's `issuer-uri` is set | Host registers `@Bean TokenValidatorFactory` |
| Decoder assembly | `OidcAccessTokenDecoderFactory` — owns the registration-count switch | Host registers `@Bean OidcAccessTokenDecoderFactory` |
| `kid` collision across JWK Sets | Primary wins via short-circuit | Host registers `@Bean JwtDecoder` with custom resolution |
| Unreachable additional URI | Lazy: WARN at decode time, fall through to the next source | None needed — the failure model is graceful by construction |
| Provider login routing | Spring Security's `/oauth2/authorization/{registrationId}` | None needed — Spring routes automatically once multiple `ClientRegistration` instances exist |

## Consequences

**Positive**

- OC can adopt the CSL filter chains without customers changing configuration: multi-IdP login routing, the flat + providers merge semantics, multi-provider token validation and multi-JWKS deployments all behave as they did in OC.
- Single-IdP hosts see no behavioural change in decoder construction — one registration takes the same Nimbus path as before, and migrating to the providers shape stays opt-in.
- Adopters whose `additional-jwk-set-uris` setting was previously ignored get the behaviour the property name implies, in both single- and multi-provider mode.
- Misconfiguration surfaces where it is cheapest to diagnose. A missing `issuer-uri` on a multi-provider deployment fails at startup naming the registration ids; an unknown `iss` at request time fails with a `BadJwtException` naming the issuer rather than an opaque 401.
- The pieces are independently testable and independently overridable. `CompositeJWKSource` is unit-tested in isolation; end-to-end decode behaviour goes through the real Spring-built beans via `ApplicationContextRunner` with local JDK `HttpServer` instances serving real RSA JWKS documents, so no network is needed. `JWSKeySelectorFactory`, `TokenValidatorFactory`, `OidcAccessTokenDecoderFactory` and `JwtDecoder` each back off to a host bean separately.

**Negative / accepted trade-offs**

- **EC algorithms are accepted on the single-URI path too.** Deployments that relied on Spring's RS256-only default now also accept EC algorithms, because every decoder path shares one algorithm set. A deliberate widening, not an oversight; hosts that must reject EC register a custom `@Bean JwtDecoder`.
- **Clock skew is not per-registration.** `TokenValidatorFactory` takes a single `Duration clockSkew`, so every registration validates timestamps with `OidcConfiguration.DEFAULT_CLOCK_SKEW` (60 s) even when providers configure different values. A standing gap, not a resolved one: hosts needing per-registration skew override `TokenValidatorFactory`.
- **A permanently unreachable additional URI is detected only when a token needs its keys.** Operators wanting startup-time validation must add their own probe. Accepted because eager probing costs startup latency and gives false confidence, and because the primary URI already behaves this way.
- **Collision semantics (providers overwrite flat) let a host shadow its flat block without noticing.** Convenient for the OC migration path, and documented in executable form by the registration-id collision test, but it is a silent overwrite.
- **`kid`-less tokens never reach the additional URIs**, in either mode, because Nimbus's `JWKSelector` matches every key in the primary set and the composite short-circuits there. The multi-provider path is not exempt: it uses the same composite per issuer, so a `kid`-less token still stops at the matched issuer's primary URI. Same behaviour as the monorepo; affected adopters register a custom `@Bean JwtDecoder`.
- **Multi-provider validation requires an iterable `ClientRegistrationRepository` and an `issuer-uri` per registration.** A multi-provider deployment configured purely with explicit endpoints and no `issuer-uri` is invalid configuration and fails at startup.
- **`CompositeJWKSource` is Camunda-owned code an extender has to understand.** Accepted: it wraps a public Nimbus interface with well-understood semantics, is unit-tested in isolation, and is the minimal port from the monorepo.

## Alternatives Considered

- **Route by `iss` with `JwtIssuerAuthenticationManagerResolver` instead of building an issuer-aware decoder.** Rejected — it produces a per-request `AuthenticationManager` wired into the filter-chain DSL, not the single `JwtDecoder` bean every CSL injection point expects; it requires discovery metadata for each issuer, which conflicts with explicit-endpoint configuration; and it offers no composition point for per-provider `additional-jwk-set-uris`. The injection-shape mismatch applies equally to within-one-issuer key rotation, where `iss` routing is not even the right question.
- **Probe additional JWK Set URIs eagerly at startup and refuse to start on failure.** Rejected — adds startup latency proportional to the slowest JWKS endpoint, gives false confidence because reachability at startup says nothing about reachability at decode time, and duplicates a failure path the composite already handles gracefully. The lazy model is what Spring and Nimbus do for the primary URI, so the operator experience stays uniform.

Consolidates records previously numbered 0015, 0020 (issuer-aware) (see git history).
