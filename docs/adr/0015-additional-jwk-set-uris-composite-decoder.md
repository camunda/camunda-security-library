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

CSL wires `additional-jwk-set-uris` into the default `JwtDecoder` via a small `CompositeJWKSource` that wraps Nimbus's `JWKSource` interface. The primary `jwk-set-uri` is queried first, then each additional URI in declared order. The first source that resolves the token's signing key wins. A failing source falls through to the next without failing the decode.

### Composition mechanism

`CompositeJWKSource<C extends SecurityContext>` implements Nimbus's `JWKSource<C>` directly. `get(JWKSelector, C)`:

1. Iterates `sources` in order.
2. For each source, calls `source.get(selector, context)`.
3. Returns the first non-empty result.
4. On `KeySourceException`, logs a warning and continues to the next source.
5. On any other (unchecked) exception, propagates immediately — these are bugs, not network failures.
6. If all sources return empty without exceptions, returns an empty list.
7. If all sources fail with `KeySourceException`, rethrows the last one so the caller sees a meaningful error message.

The decoder construction in `OidcBeansConfiguration#jwtDecoder` builds one Nimbus `JWKSource` per URI via `JWKSourceBuilder.create(url).refreshAheadCache(false).rateLimited(false).cache(true).build()` — the same settings Spring's `NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder` uses internally. The composite source is plugged into a `JWSVerificationKeySelector` with the standard RSA + EC algorithm family, and the resulting `JWSKeySelector` is set on a `DefaultJWTProcessor` consumed by `new NimbusJwtDecoder(jwtProcessor)`.

### Discovery vs explicit primary

When `additional-jwk-set-uris` is non-empty, an **explicit** primary `jwk-set-uri` must be set. Discovery via `issuer-uri` is not supported in combination with additional URIs — the discovery path uses `NimbusJwtDecoder.withIssuerLocation(...)` which constructs its own internal `JWKSource` and does not expose a composition hook. Hosts that rely on discovery and need additional URIs must set `jwk-set-uri` explicitly (it may point at the same endpoint the discovery document would resolve to). The error message is explicit:

> Cannot build JwtDecoder with additional-jwk-set-uris when the primary jwk-set-uri is unset: set `camunda.security.authentication.oidc.jwk-set-uri` (or `providers.oidc.<id>.jwk-set-uri`) explicitly. Discovery via issuer-uri is not supported when additional-jwk-set-uris is configured.

### Why not a Spring or Nimbus built-in

Investigated and rejected:

- **`NimbusJwtDecoder.withJwkSetUri(uri)`** — accepts only one URI. The builder does not expose a hook for replacing the underlying `JWKSource`. Cannot satisfy the requirement.
- **`Nimbus JWKSourceBuilder`** — single URL per builder. There is no Nimbus-provided composite. The closest primitives are `URLBasedJWKSetSource` (single URL) and `JWKSetSource` chaining APIs that target retry/cache concerns, not source composition.
- **Spring's `JwtIssuerAuthenticationManagerResolver`** — routes by `iss` claim at the **filter** level, returning a different `AuthenticationManager` (and therefore a different `JwtDecoder`) per request. Wrong shape for this issue (it is `iss`-routed, not within-one-issuer key rotation) and wrong injection shape for CSL generally (the library exposes a single `@Bean JwtDecoder` injected throughout the resource-server chain). The same injection-shape mismatch applies to #221 (issuer-aware decoder), where the multi-IdP problem is genuinely `iss`-routed but still needs to surface as a single `JwtDecoder` bean — that ADR will document its own custom selector for the same reason.

The `CompositeJWKSource` is ~40 lines of code that wraps a public Nimbus interface (`JWKSource<C>`) with well-understood semantics. There is no Spring or Nimbus built-in that does this; the alternative would be a custom HTTP client that fetches each URL, merges keys, and re-implements caching — significantly more code and risk than the small composite class.

### Behaviour when an additional URI is unreachable

Lazy by design. `JWKSourceBuilder.create(url).cache(true).build()` does not perform a startup probe — the URL is fetched on the first matching token. If an additional URI is unreachable at first use, the source throws a `KeySourceException`; the composite logs at WARN, the next source is tried, and the primary URI continues to validate tokens normally. There is no startup-time validation of additional URIs.

This deliberately diverges from the issue's original wording ("logs a warning at startup but does not prevent the primary chain from validating tokens"). Reasons:

- A startup probe would require eagerly fetching each URL, which (a) blocks startup on every additional URI's network latency, and (b) gives false confidence — a URI reachable at startup can go down five minutes later. The composite already handles runtime failures gracefully.
- Spring and Nimbus's own default JWK source path is lazy. Aligning with that keeps the failure model uniform: the host sees the same kind of log at the same point regardless of which URI failed.

The semantics ("a failing source does not break the others") are still satisfied — just at decode time rather than startup.

### Uniform algorithm set across all decoder paths

All three decoder paths — single-URI, discovery, composite — use the same RSA + EC family algorithm set (`RS256/384/512`, `ES256/384/512`). This deliberately overrides Spring's narrower `NimbusJwtDecoder.withJwkSetUri(...).build()` default (RS256-only) on the non-composite paths by calling `.jwsAlgorithm(...)` for each algorithm on the Spring builder. Reasons:

- **Match the monorepo.** The monorepo's [`JWSKeySelectorFactory`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/JWSKeySelectorFactory.java) uses the same RSA+EC set everywhere. Adopters relying on EC algorithms today regress on OC adoption (#38) if CSL defaults to RS256-only.
- **No silent drift when enabling `additional-jwk-set-uris`.** A host that adds the property should not discover that the composite path quietly accepts ES256 tokens that the single-URI path rejected. Aligning both paths to the broader set removes that surprise.
- **Industry-default coverage.** RS256/384/512 + ES256/384/512 covers every algorithm a public-issuer IdP is likely to use; rejecting EC by default would be more surprising than accepting it.

Hosts that want a narrower set should register their own `@Bean JwtDecoder` — the `@ConditionalOnMissingBean` back-off keeps that path open.

### `kid` collision: primary wins

When multiple JWK Sets publish a key with the same `kid` (unlikely but possible during a rotation), the **first source that returns a non-empty match wins**. Since the primary `jwk-set-uri` is always queried first and the composite short-circuits on the first non-empty result, the primary's key is used. Adopters who need to override this should reorder their `additional-jwk-set-uris` — but in practice `kid` values are designed to be unique per signing key.

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
- The composition mechanism (`CompositeJWKSource`) is small, isolated, and unit-tested in `CompositeJWKSourceTest`. The wiring in `OidcBeansConfiguration` is gated on a non-empty list — empty lists are a no-op, so existing single-JWKS deployments see no behavioural change.
- Lazy failure handling matches Spring's defaults and produces the same operator experience adopters already have with the primary `jwk-set-uri`.
- The mechanism composes naturally with the future issuer-aware decoder (#221): the per-issuer additional-URIs map there will populate one `CompositeJWKSource` per issuer.

**Negative / accepted trade-offs**

- An additional URI that is permanently unreachable is detected only when a token requires its keys. Operators relying on startup-time validation will need to add their own probe (the lazy model is consistent with how the primary URI behaves too). Accepted because eager probing has its own downsides (latency, false-confidence).
- Discovery via `issuer-uri` is incompatible with `additional-jwk-set-uris`. Hosts that want both must set `jwk-set-uri` explicitly. Accepted because the discovery path (`NimbusJwtDecoder.withIssuerLocation`) does not expose a JWKSource composition hook, and reaching into Spring internals to retro-fit one would couple CSL to Spring's `NimbusJwtDecoder` private APIs.
- A custom `CompositeJWKSource` class is "Camunda-owned magic" that adopters must understand if they extend the library. Accepted because the class wraps a public Nimbus interface with well-understood semantics, is unit-tested in isolation, and is the minimal port from the monorepo. The investigation summary above documents why no Spring/Nimbus built-in is suitable.

## Alternatives Considered

- **Pin nimbus-jose-jwt as a runtime-only transitive and write the composite against `Object`-typed lambdas.** Rejected — opaque code, no compile-time type safety, and the transitive version still needs pinning to keep the test classpath aligned with runtime. The explicit `nimbus-jose-jwt` dependency (managed in the parent pom) is a cleaner expression of the same fact.
- **Use `JwtIssuerAuthenticationManagerResolver` instead.** Rejected — wrong scope for this issue (it is `iss`-routed, not within-one-issuer key rotation) and wrong injection shape for CSL generally (see "Why not a Spring or Nimbus built-in" above). The injection-shape mismatch will recur in #221, which also wants a single `JwtDecoder` bean despite genuinely needing `iss` routing.
- **Implement a custom `JWKSetSource` extending Nimbus's caching primitives.** Rejected — significantly more code than the composite, duplicates Nimbus's own cache layer, and entangles CSL with Nimbus's internal extension points (subject to breaking changes between Nimbus minors).
- **Probe additional URIs eagerly at startup.** Rejected — adds startup latency proportional to the worst-case JWKS endpoint, gives false confidence, and the runtime composite already handles failures gracefully. The original issue wording was aspirational; the lazy model is operationally equivalent.
- **Allow `additional-jwk-set-uris` with `issuer-uri` discovery (no explicit `jwk-set-uri`).** Rejected — `NimbusJwtDecoder.withIssuerLocation(...)` builds its own internal `JWKSource` with no composition hook. Retro-fitting one would require either reaching into Spring's private APIs or duplicating the discovery flow. Easier to require the explicit `jwk-set-uri` and document it.
- **Port the monorepo's full `OidcAccessTokenDecoderFactory` and `JWSKeySelectorFactory` classes verbatim.** Deferred — the issuer-aware portion of those factories belongs to #221, and the at+jwt type header support belongs to #220. This ADR limits scope to the composite path. Once #220 and #221 land, the wiring may consolidate into a single factory class.
