---
status: Accepted
---

# ADR-0036: Per-chain JwtAuthenticationConverter hook on ScopedApiSecurityChainBuilder

**Deciders**: Ben Sheppard

## Status

Accepted

## Context

`ScopedApiSecurityChainBuilder.buildOidcApiChainWith` wires `oauth2ResourceServer(oauth2 ->
oauth2.jwt(jwt -> jwt.decoder(jwtDecoder))...)` for every OIDC API chain it builds. There was no
way for a host to supply a custom `Converter<Jwt, Authentication>` (Spring Security's
`JwtAuthenticationConverter` seam) — the chain always fell back to Spring Security's default
claim-to-authority mapping (the `scope`/`scp` claim).

A host may need multiple simultaneous OIDC API chains in the same application, each requiring a
*different* converter — for example, distinct chains for API v1 and API v2, where each version
maps JWT claims to authorities differently. This rules out a single global override: any hook
that resolves to one bean-per-application — a `@ConditionalOnMissingBean` override, or a
`@FunctionalInterface` collected via `ObjectProvider` and applied identically to every chain, as
`HttpsRedirectCustomizer` and `OidcResourceServerCustomizer` both do (see
[ADR-0034](0034-cors-and-https-redirect-host-hooks.md)) — cannot express "chain A gets converter X,
chain B gets converter Y" within one running application.

This gap was surfaced while scoping camunda/camunda-hub's P7 phase-swap
(camunda-security-library#308): Hub's `PublicApiSecurityConfiguration` builds three
`SecurityFilterChain`s (v1, v2-enabled, v2-disabled), each needing its own
`@Qualifier("publicApi") Converter<Jwt, Authentication>`. Tracked as #537.

The converter's public type is `Converter<Jwt, Authentication>` (matching how hosts naturally
declare it — see Hub's `@Qualifier("publicApi") Converter<Jwt, Authentication>` bean below), but
Spring Security's actual `JwtConfigurer#jwtAuthenticationConverter` requires a `Converter<Jwt, ?
extends AbstractAuthenticationToken>`. Every host that has needed this seam so far (Hub included)
has had to hand-write the same adapter: call the converter, and if the result isn't an
`AbstractAuthenticationToken`, throw `InvalidBearerTokenException` so the request fails as a clean
401 instead of an uncaught `ClassCastException`. This adapter is now centralized inside
`ScopedApiSecurityChainBuilder` (`toAbstractAuthenticationTokenConverter`) so hosts no longer write
it themselves.

## Decision

Add the converter as a **per-invocation method parameter**, not a globally-registered customizer
bean — mirroring the existing `Supplier<JwtDecoder> oidcDecoderSupplier` parameter already used by
`buildScopedApiChain` for exactly the same reason (per-scope decoder selection).

Two new overloads are added, each with one more parameter than an existing overload (never the
same arity as an existing overload, to avoid Java overload-resolution ambiguity when a caller
passes `null` positionally):

- `buildOidcApiChain(HttpSecurity, Collection<String>, Collection<String>, JwtDecoder,
  Converter<Jwt, Authentication>, SessionRepositoryFilter<?>)` — 6-arg, alongside the existing
  4-arg and 5-arg (decoder-only) overloads.
- `buildScopedApiChain(HttpSecurity, String, AuthenticationConfiguration, Supplier<JwtDecoder>,
  Supplier<Converter<Jwt, Authentication>>, SessionRepositoryFilter<?>)` — 6-arg, alongside the
  existing 4-arg and 5-arg (decoder-supplier-only) overloads.

A `null` converter (or a converter supplier returning `null`) means "no override" — the builder
does not call `.jwtAuthenticationConverter(...)` at all in that case, so Spring Security's default
behavior applies exactly as it did before this change. All pre-existing overloads delegate to the
new ones with a null converter, so no existing caller's behavior changes.

The converter *supplier* reference itself (for the scoped-chain overload) is mandatory —
`Objects.requireNonNull`, matching `oidcDecoderSupplier`'s treatment — but unlike the decoder
supplier, the converter supplier's *result* is allowed to be `null`. This asymmetry is intentional:
a decoder is required for the chain to function at all; a converter is genuinely optional.

## Consequences

**Positive**

- Hosts needing distinct per-chain authority mapping (e.g. multiple API versions) can now express
  that without CSL changes on their side beyond passing the parameter.
- Zero behavior change for every existing caller — no existing overload's signature or behavior
  changed.
- Consistent with the existing `oidcDecoderSupplier` precedent already established for
  `buildScopedApiChain`.
- The `Converter<Jwt, Authentication>` → `Converter<Jwt, AbstractAuthenticationToken>` adapter that
  every host previously hand-wrote is now centralized in CSL, so hosts migrating onto this hook can
  delete their own copy.

**Negative / accepted trade-offs**

- `ScopedApiSecurityChainBuilder` now has two overloads per entry point instead of one, growing the
  builder's public surface. Accepted because the alternative (a global customizer) cannot express
  the motivating multi-chain use case at all.
- Unlike `HttpsRedirectCustomizer`/`OidcResourceServerCustomizer`, this hook is not
  `ObjectProvider`-discoverable — a host must thread the converter through to the call site
  explicitly (typically via its own `@Bean` method parameter with `@Qualifier`, as Hub's
  `PublicApiSecurityConfiguration` already does). This is consistent with `oidcDecoderSupplier`,
  which has the same shape.
- A converter that returns an `Authentication` which is not an `AbstractAuthenticationToken` fails
  the request as a 401 (`InvalidBearerTokenException`) rather than at compile time — this is a
  runtime contract, not enforced by the type system, matching the constraint every host already
  lived with before this change.

## Alternatives Considered

- **Global `ObjectProvider<Converter<Jwt, Authentication>>` bean, `HttpsRedirectCustomizer`-style.**
  Rejected — applies identically to every chain in the application; cannot express "chain A gets
  converter X, chain B gets converter Y" within one running application, which is exactly the
  motivating use case (Hub's per-API-version converters).
- **`@ConditionalOnMissingBean` single-slot override, `CorsConfigurationSource`-style.** Rejected
  for the same reason — one bean, one converter, application-wide.
- **Extend `OidcResourceServerCustomizer` and let hosts call `oauth2.jwt(jwt ->
  jwt.jwtAuthenticationConverter(...))` themselves from inside a customizer.** Rejected — that
  hook is a shared, `@Order`-composed list applied to every chain (see
  [ADR-0034](0034-cors-and-https-redirect-host-hooks.md) and the `docs/adopters/security-filter-chains.md`
  entry for `OidcResourceServerCustomizer`), not parameterized by scope or chain identity. A host
  could technically call the converter setter from inside a customizer today, but there is no way
  to select "only this specific chain gets this converter" — every registered customizer runs on
  every chain.
- **Change the public parameter type to `Converter<Jwt, ? extends AbstractAuthenticationToken>`
  directly, matching Spring Security's actual requirement.** Rejected — every host that has needed
  this seam declares it as `Converter<Jwt, Authentication>` (the more natural, less
  Spring-Security-internals-aware type), and Hub's existing bean is already typed that way. Keeping
  the public type as `Authentication` and adapting internally means hosts migrating onto this hook
  don't need to change their existing bean's type, only delete their own hand-written adapter.
