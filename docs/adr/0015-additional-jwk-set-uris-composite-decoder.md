---
status: Accepted
---

# ADR-0015: Composite JWK source for `additional-jwk-set-uris` in the default JwtDecoder

**Deciders**: Ben Sheppard

## Status

Accepted

## Context

The `camunda.security.authentication.oidc.additional-jwk-set-uris` property has existed on the CSL config surface since the initial OIDC work but was documented as "Reserved for multi-JWKS-source hosts; not consumed by the default beans." Adopters who configured it had no behavioural effect — every token validation request still went to the single `jwk-set-uri`.

Two motivating use cases:

1. **Key rotation across multiple JWK Set endpoints.** Some IdPs publish a primary JWKS plus a secondary endpoint during a rotation window (or a federated identity provider hosting keys from multiple back-end stores). Validating tokens during the window requires consulting both.
2. **Monorepo parity.** The camunda monorepo already supports this via [`OidcAccessTokenDecoderFactory`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/OidcAccessTokenDecoderFactory.java), [`JWSKeySelectorFactory`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/JWSKeySelectorFactory.java), and a small `CompositeJWKSource`. Deployments that rely on the property today regress on OC adoption (#38) unless CSL wires the same behaviour.

[ADR-0013](0013-multi-idp-oidc-configuration.md) introduced multi-IdP `ClientRegistration` aggregation but explicitly punted on per-issuer `JwtDecoder` routing ("the library refuses to guess across multiple providers"). This ADR is **independent of** that decision — `additional-jwk-set-uris` is per-`OidcConfiguration`, so it works for the flat block, for a single `providers.oidc.<id>` entry that is the chosen decoder source, or (once issue #221 lands) per-issuer in a multi-IdP decoder.

The core questions this ADR answers:

> 1. What composition mechanism is correct for "primary + N additional JWK Set URIs"?
> 2. Why not use a built-in Spring / Nimbus primitive instead of porting a custom class?
> 3. What happens when one of the configured URIs is unreachable?

## Decision

CSL wires `additional-jwk-set-uris` into the default `JwtDecoder` via a small `CompositeJWKSource` that wraps Nimbus's `JWKSource` interface. The primary `jwk-set-uri` is queried first, then each additional URI in declared order. The first source that resolves the token's signing key wins. A failing source falls through to the next without failing the decode. As part of the same change, all three decoder paths — single-URI, discovery, and composite — are aligned on a single RSA + EC algorithm set (`RS256/384/512`, `ES256/384/512`) so the algorithm acceptance does not depend on which path the configuration triggers.

`CompositeJWKSource<C extends SecurityContext>` (package-private in `io.camunda.security.spring.oidc`) implements Nimbus's `JWKSource<C>` directly. `get(JWKSelector, C)`:

1. Iterates `sources` in declared order.
2. For each source, calls `source.get(selector, context)`.
3. Returns the first non-empty result.
4. On `KeySourceException`, logs a warning (distinguishing "trying next source" from "no further sources to try" on the final element) and continues to the next source.
5. On any other (unchecked) exception, propagates immediately — these are bugs, not network failures.
6. If all sources return empty without exceptions, returns an empty list.
7. If all sources fail with `KeySourceException`, rethrows the last one so the caller sees a meaningful error message.

The decoder construction in `OidcBeansConfiguration#jwtDecoder` builds one Nimbus `JWKSource` per URI via `JWKSourceBuilder.create(url).refreshAheadCache(false).rateLimited(false).cache(true).build()` — the same settings Spring's `NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder` uses internally. The composite source is plugged into a `JWSVerificationKeySelector` with the uniform RSA + EC algorithm set, and the resulting `JWSKeySelector` is set on a `DefaultJWTProcessor` consumed by `new NimbusJwtDecoder(jwtProcessor)`. The single-URI and discovery paths still go through Spring's `NimbusJwtDecoder.withJwkSetUri(...)` / `withIssuerLocation(...)` builders, but call `.jwsAlgorithm(...)` for each algorithm in the uniform set so all three paths accept the same set.

When `additional-jwk-set-uris` is non-empty, an **explicit** primary `jwk-set-uri` must be set. Discovery via `issuer-uri` alone is incompatible with the composite path. Startup fails with an actionable error:

> Cannot build JwtDecoder with additional-jwk-set-uris when the primary jwk-set-uri is unset: set `camunda.security.authentication.oidc.jwk-set-uri` (or `providers.oidc.<id>.jwk-set-uri`) explicitly. Discovery via issuer-uri is not supported when additional-jwk-set-uris is configured.

### Why these particular boundaries

- **Custom `CompositeJWKSource` over a Spring/Nimbus built-in.** `NimbusJwtDecoder.withJwkSetUri(uri)` accepts only one URI and exposes no hook for replacing the underlying `JWKSource`. Nimbus's `JWKSourceBuilder` is single-URL only. `JwtIssuerAuthenticationManagerResolver` routes by `iss` at the filter level (wrong scope: this issue is within-one-issuer key rotation, not `iss` routing; and wrong injection shape: CSL exposes a single `@Bean JwtDecoder`, not a per-request `AuthenticationManager`). The composite class is ~40 lines wrapping a public Nimbus interface; the only alternative is a custom HTTP client that re-implements caching, which would be significantly more code and risk.
- **Composition by primary-first short-circuit.** Querying sources in declared order with first-non-empty-wins keeps the `kid` collision policy unambiguous ("primary wins") and lets adopters re-order URIs to change precedence. The alternative (merging all keys before selection) would force the host to keep `kid` values globally unique across endpoints, which is operationally fragile during a rotation window.
- **Require an explicit `jwk-set-uri` when additional URIs are set.** `NimbusJwtDecoder.withIssuerLocation(...)` builds its own internal `JWKSource` with no composition hook. Retro-fitting a composite onto the discovery path would require reaching into Spring's private APIs or duplicating the discovery flow. Requiring `jwk-set-uri` explicitly is the smaller commitment and the error message tells the host exactly what to do.
- **Lazy failure on unreachable additional URIs, not eager startup probe.** Eager probing would block startup on each URI's network latency and give false confidence (a URI reachable at startup can go down five minutes later). The composite already handles runtime failures gracefully — a failing source logs WARN and the next is tried. Spring's and Nimbus's own JWK source paths are lazy; aligning with that keeps the operator failure model uniform. The original issue wording ("warning at startup") was aspirational.
- **Uniform RSA + EC algorithm set on all three decoder paths.** Single-URI, discovery, and composite paths share `RS256/384/512` + `ES256/384/512`. This is a **deliberate behavioural change** — Spring's `NimbusJwtDecoder.withJwkSetUri(...).build()` defaults to RS256-only, so existing single-URI deployments that relied on the default now also accept EC algorithms. Three reasons override the cost:
  - The monorepo's [`JWSKeySelectorFactory`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/JWSKeySelectorFactory.java) uses this same wider set everywhere; adopters relying on EC today regress on OC adoption (#38) if CSL defaults to RS256-only.
  - A host that adds `additional-jwk-set-uris` should not discover that the composite path quietly accepts EC tokens the single-URI path rejected. Aligning both paths to the same set removes that surprise.
  - RS256/384/512 + ES256/384/512 covers every algorithm a public-issuer IdP is likely to use. Rejecting EC by default would be more surprising than accepting it.

  Hosts that need a narrower set must register their own `@Bean JwtDecoder` — the `@ConditionalOnMissingBean` back-off keeps that path clean.

### Default implementations and override boundaries

| Concern | Default | Override path |
|---|---|---|
| `JwtDecoder` when `additional-jwk-set-uris` is empty | `NimbusJwtDecoder.withJwkSetUri(...)` or `withIssuerLocation(...)` — unchanged | Host registers `@Bean JwtDecoder` (`@ConditionalOnMissingBean`) |
| `JwtDecoder` when `additional-jwk-set-uris` is non-empty | `NimbusJwtDecoder(jwtProcessor)` with `JWSKeySelector` backed by `CompositeJWKSource` | Same — host registers `@Bean JwtDecoder` |
| `kid` collision policy | Primary wins via short-circuit | Host registers `@Bean JwtDecoder` with custom resolution |
| Unreachable additional URI | Lazy: WARN at decode time, fall through to next source | None needed — failure model is graceful by construction |

## Consequences

**Positive**

- Adopters whose `additional-jwk-set-uris` setting was silently ignored now get the behaviour the property name suggests. OC adoption (#38) preserves multi-JWKS deployments without code changes.
- The composition mechanism (`CompositeJWKSource`) is small, isolated, and unit-tested in `CompositeJWKSourceTest`. End-to-end decode behaviour through the real Spring-built bean is covered by `OidcBeansConfigurationCompositeJwtDecodeTest` (two local JDK `HttpServer` instances serving real RSA JWKS documents).
- Lazy failure handling matches Spring's defaults and produces the same operator experience adopters already have with the primary `jwk-set-uri`.
- The mechanism composes naturally with the future issuer-aware decoder (#221): the per-issuer additional-URIs map there will populate one `CompositeJWKSource` per issuer.

**Negative / accepted trade-offs**

- **Accepted EC algorithms even on the single-URI path.** Existing single-URI deployments that relied on Spring's RS256-only default now also accept EC algorithms because all three decoder paths use the same uniform algorithm set. This is a deliberate behavioural change, not a no-op — see the "Why these particular boundaries" entry on the uniform algorithm set. Hosts that need to reject EC must register a custom `@Bean JwtDecoder`.
- An additional URI that is permanently unreachable is detected only when a token requires its keys. Operators relying on startup-time validation will need to add their own probe (the lazy model is consistent with how the primary URI behaves too). Accepted because eager probing has its own downsides (latency, false-confidence).
- Discovery via `issuer-uri` is incompatible with `additional-jwk-set-uris`. Hosts that want both must set `jwk-set-uri` explicitly. Accepted because the discovery path (`NimbusJwtDecoder.withIssuerLocation`) does not expose a JWKSource composition hook, and reaching into Spring internals to retro-fit one would couple CSL to Spring's `NimbusJwtDecoder` private APIs.
- A custom `CompositeJWKSource` class is "Camunda-owned magic" that adopters must understand if they extend the library. Accepted because the class wraps a public Nimbus interface with well-understood semantics, is unit-tested in isolation, and is the minimal port from the monorepo. The "Why these particular boundaries" section documents why no Spring/Nimbus built-in is suitable.

## Alternatives Considered

- **Pin nimbus-jose-jwt as a runtime-only transitive and write the composite against `Object`-typed lambdas.** Rejected — opaque code, no compile-time type safety, and the transitive version still needs pinning to keep the test classpath aligned with runtime. The explicit `nimbus-jose-jwt` dependency (managed in the parent pom) is a cleaner expression of the same fact.
- **Use `JwtIssuerAuthenticationManagerResolver` instead.** Rejected — wrong scope for this issue (it is `iss`-routed, not within-one-issuer key rotation) and wrong injection shape for CSL generally (see "Why not a Spring or Nimbus built-in" above). The injection-shape mismatch will recur in #221, which also wants a single `JwtDecoder` bean despite genuinely needing `iss` routing.
- **Implement a custom `JWKSetSource` extending Nimbus's caching primitives.** Rejected — significantly more code than the composite, duplicates Nimbus's own cache layer, and entangles CSL with Nimbus's internal extension points (subject to breaking changes between Nimbus minors).
- **Probe additional URIs eagerly at startup.** Rejected — adds startup latency proportional to the worst-case JWKS endpoint, gives false confidence, and the runtime composite already handles failures gracefully. The original issue wording was aspirational; the lazy model is operationally equivalent.
- **Allow `additional-jwk-set-uris` with `issuer-uri` discovery (no explicit `jwk-set-uri`).** Rejected — `NimbusJwtDecoder.withIssuerLocation(...)` builds its own internal `JWKSource` with no composition hook. Retro-fitting one would require either reaching into Spring's private APIs or duplicating the discovery flow. Easier to require the explicit `jwk-set-uri` and document it.
- **Port the monorepo's full `OidcAccessTokenDecoderFactory` and `JWSKeySelectorFactory` classes verbatim.** Deferred — the issuer-aware portion of those factories belongs to #221, and the at+jwt type header support belongs to #220. This ADR limits scope to the composite path. Once #220 and #221 land, the wiring may consolidate into a single factory class.
