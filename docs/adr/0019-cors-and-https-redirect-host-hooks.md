---
status: Accepted
---

# ADR-0019: Host customization hooks for security filter chains

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

CSL centralises filter chain construction ([ADR-0006](0006-no-spring-boot-auto-configuration.md)),
but several behaviours vary by host and deployment environment and cannot be decided by the
library itself: CORS policy, HTTP→HTTPS redirect strategy, dynamic or route-varying response
headers (including CSP nonces), and per-chain JWT authority mapping.

CSL previously hard-coded `.cors(AbstractHttpConfigurer::disable)` on every filter chain and applied
a fixed, static set of response headers via `camunda.security.http-headers.*`. Host applications had
no way to enable CORS, insert an HTTPS redirect filter, generate a per-request CSP nonce, vary
headers by route, or supply a different JWT-authority-mapping converter to different simultaneous
API chains.

The JWT-converter and header gaps were surfaced while scoping camunda/camunda-hub's P7 phase-swap
(camunda-security-library#308): Hub's `PublicApiSecurityConfiguration` builds three
`SecurityFilterChain`s (v1, v2-enabled, v2-disabled) each needing its own
`@Qualifier("publicApi") Converter<Jwt, Authentication>` (tracked as #537), and Hub's
`WebSecurityConfiguration` builds a fresh CSP nonce per request and varies `frame-ancestors`/
`X-Frame-Options` by route (tracked as #538/#539) — none of which CSL's static configuration could
express.

What hook shapes let a host plug host-specific, non-opinionated behaviour into chains CSL owns,
without CSL hard-coding origins, a redirect strategy, a fixed header set, or a single
application-wide authority-mapping rule?

## Decision

Four hooks address the four gaps. Three share one registration shape; the fourth deliberately
diverges because its motivating use case cannot be expressed by that shape.

### CORS hook — `CorsConfigurationSource` bean override

`CorsBeansConfiguration` provides a `@ConditionalOnMissingBean CorsConfigurationSource` default: an
instance of `NoOpCorsConfigurationSource`, a dedicated marker subtype of
`UrlBasedCorsConfigurationSource` with no registered mappings.

`SecurityFilterChainSupport.applyCorsConfiguration` checks for the marker via `instanceof
NoOpCorsConfigurationSource`:

- If the marker is present (CSL default): disables CORS via `.cors(disable)`, preserving the
  previous behaviour.
- Otherwise (host bean): enables CORS and wires the host source into the chain.

A host enables CORS by registering any `CorsConfigurationSource` bean; `@ConditionalOnMissingBean`
on the CSL default ensures it backs off automatically.

The marker subtype (rather than checking for an empty `UrlBasedCorsConfigurationSource`) is
intentional: a host that provides its own initially-empty `UrlBasedCorsConfigurationSource` and
populates it after context refresh would otherwise be silently ignored by an emptiness check. The
marker subtype still technically accepts `registerCorsConfiguration` calls — it extends
`UrlBasedCorsConfigurationSource` and inherits the method — but any mappings registered on it are
silently ignored because `applyCorsConfiguration` keys on the marker *type*, not on whether mappings
are present. This is documented on `NoOpCorsConfigurationSource`'s own Javadoc as a footgun: hosts
must register their own `CorsConfigurationSource` bean to enable CORS, not mutate the default.

### `HttpsRedirectCustomizer` and `SecurityHeadersCustomizer` — shared `ObjectProvider`-collected hooks

Both are `@FunctionalInterface`s receiving full `HttpSecurity`, collected via `ObjectProvider` and
applied in `@Order` order; no bean present is a no-op.

- `HttpsRedirectCustomizer` — a host registers a bean to insert an HTTP→HTTPS redirect filter into
  every CSL filter chain. No bean means no redirect: CSL's default is to leave that policy to the
  host's infrastructure layer (load balancer, ingress). This follows the established
  `OidcResourceServerCustomizer` pattern (see [ADR-0006](0006-no-spring-boot-auto-configuration.md))
  and requires no CSL changes when a host adds or removes a redirect strategy.
- `SecurityHeadersCustomizer` closes both the CSP and general-headers gaps with a single interface:
  CSP is, mechanically, just another response header. A host implements nonce generation or
  per-route header variation entirely inside its own bean (typically a custom `HeaderWriter` added
  via `http.headers(headers -> headers.addHeaderWriter(...))`), the same shape
  `HttpsRedirectCustomizer` implementations use for their own filter. The hook itself doesn't need
  to be scope-parameterized because the host's own `HeaderWriter`/filter already runs per-request and
  can inspect the request to decide what to do per route.

A single hook exists for headers, not two, because the two candidate interfaces considered during
design (`CspCustomizer` and `SecurityHeadersCustomizer`) would have been byte-for-byte identical
(`void customize(HttpSecurity)`), applied back-to-back at the same call sites in the same fixed
order — the only distinction would have been naming intent, which doesn't justify a second public
SPI surface to support indefinitely.

`SecurityHeadersCustomizer` is applied immediately after `setupSecureHeaders(...)` and coexists with
it: a host's custom `HeaderWriter` is additive via `addHeaderWriter`, not a replacement, so
`camunda.security.http-headers.*` (including `content-security-policy.*`) keeps working for hosts
that don't need dynamic behaviour, unless the host's own writer overwrites the same header.

### `JwtAuthenticationConverter` — per-chain hook (diverges from the shared shape)

`ScopedApiSecurityChainBuilder.buildOidcApiChainWith` wires `oauth2ResourceServer(oauth2 ->
oauth2.jwt(jwt -> jwt.decoder(jwtDecoder))...)` for every OIDC API chain it builds, with no way for
a host to supply a custom `Converter<Jwt, Authentication>` (Spring Security's
`JwtAuthenticationConverter` seam) — chains fell back to Spring Security's default claim-to-authority
mapping.

A host may need multiple simultaneous OIDC API chains in the same application, each requiring a
*different* converter — Hub's per-API-version converters (v1, v2-enabled, v2-disabled) are the
motivating case. **No hook that resolves to one bean per application — neither a
`@ConditionalOnMissingBean` single-slot override nor an `ObjectProvider`-collected shared list
applied identically to every chain, as `HttpsRedirectCustomizer` and `SecurityHeadersCustomizer`
both are — can express "chain A gets converter X, chain B gets converter Y" within one running
application.** This is why this hook is a **per-invocation method parameter** instead, mirroring the
existing `Supplier<JwtDecoder> oidcDecoderSupplier` parameter `buildScopedApiChain` already used for
exactly the same reason (per-scope decoder selection).

Two new overloads are added, each with a different arity from every pre-existing overload (never the
same arity as an existing one, to avoid Java overload-resolution ambiguity when a caller passes
`null` positionally):

- `buildOidcApiChain(HttpSecurity, Collection<String>, Collection<String>, JwtDecoder,
  Converter<Jwt, Authentication>, SessionRepositoryFilter<?>)` — 6-arg, alongside the existing 4-arg
  and 5-arg (decoder-only) overloads.
- `buildScopedApiChain(HttpSecurity, String, AuthenticationConfiguration, Supplier<JwtDecoder>,
  Supplier<Converter<Jwt, Authentication>>, SessionRepositoryFilter<?>)` — 6-arg, alongside the
  existing 4-arg and 5-arg (decoder-supplier-only) overloads.

A `null` converter (or a converter supplier returning `null`) means "no override" — the builder does
not call `.jwtAuthenticationConverter(...)` at all in that case, so Spring Security's default
behaviour applies exactly as before. All pre-existing overloads delegate to the new ones with a
`null` converter, so no existing caller's behaviour changes.

For the scoped-chain overload, the converter *supplier reference* itself is mandatory
(`Objects.requireNonNull`, matching `oidcDecoderSupplier`'s treatment), but unlike the decoder
supplier, the supplier's *result* may be `null`. This asymmetry is intentional: a decoder is required
for the chain to function at all; a converter is genuinely optional.

The converter's public type is `Converter<Jwt, Authentication>` — matching how hosts naturally
declare it (e.g. Hub's `@Qualifier("publicApi") Converter<Jwt, Authentication>` bean) — but Spring
Security's actual `JwtConfigurer#jwtAuthenticationConverter` requires a `Converter<Jwt, ? extends
AbstractAuthenticationToken>`. Every host that has needed this seam had hand-written the same
adapter: call the converter, and if the result isn't an `AbstractAuthenticationToken`, throw
`InvalidBearerTokenException` so the request fails as a clean 401 instead of an uncaught
`ClassCastException`. This adapter is now centralised inside `ScopedApiSecurityChainBuilder`
(`toAbstractAuthenticationTokenConverter`), enforced at runtime (not compile time) — hosts migrating
onto this hook can delete their own copy.

**Last-writer-wins ordering caveat.** The per-chain converter and any host-registered
`OidcResourceServerCustomizer` write to the same `jwtAuthenticationConverter(...)` setter on the same
`JwtConfigurer`, and the customizer runs *after* the per-chain converter is set — so a customizer
that also calls that setter silently overrides the per-chain converter. No shipped customizer does
this today, and the same precedence already held for `jwtDecoder(...)` before this change, so
nothing regresses — but a host combining both hooks on one chain should know the ordering.

### Decision matrix — four hooks, two shapes

| Hook | Registration shape | Why this shape | Applies to |
|---|---|---|---|
| `CorsConfigurationSource` | `@ConditionalOnMissingBean` single bean override, keyed off a `NoOpCorsConfigurationSource` marker | Host controls origins, not just an on/off toggle; the marker distinguishes "no host config yet" from "host config is genuinely empty" | All chains, including the catch-all deny-all chain — **10** call sites (`applyCorsConfiguration`) |
| `HttpsRedirectCustomizer` | `ObjectProvider`-collected, `@Order`-composed shared bean(s) | Redirect policy is uniform across an application; matches the existing `OidcResourceServerCustomizer` precedent | All chains, including the catch-all deny-all chain — **10** call sites (`applyHttpsRedirectCustomizers`) |
| `SecurityHeadersCustomizer` | `ObjectProvider`-collected, `@Order`-composed shared bean(s) | Same shape as `HttpsRedirectCustomizer`; header/CSP behaviour is not genuinely per-chain-instance, so a shared bean with route-based logic inside the host's own `HeaderWriter` is sufficient | Content-serving chains only — **9** call sites (`setupSecureHeaders` / `applySecurityHeadersCustomizers`), one fewer than the CORS/redirect hooks because the catch-all deny-all chain serves no content and has no `setupSecureHeaders` call |
| `JwtAuthenticationConverter` (via `buildOidcApiChain`/`buildScopedApiChain`) | Per-invocation method parameter, not a bean | Multiple simultaneous chains can need *different* converters; no bean-per-application shape can express that | Per-chain-instance — only the specific chain the host builds with the 6-arg overload |

### Applied to all chains, including the catch-all deny-all chain (CORS and HTTPS redirect)

The CORS and HTTPS-redirect hooks are applied to every filter chain, including
`protectedUnhandledPathsSecurityFilterChain` (the lowest-priority `/**` deny-all chain). This is
intentional: a host-provided `CorsConfigurationSource` with a broad `/**` mapping must handle
preflight `OPTIONS` requests even for paths that don't match any other chain; restricting the hooks
to "content-serving" chains would silently miss those preflight requests. `SecurityHeadersCustomizer`
is *not* applied there, because the catch-all chain serves no content and has no `setupSecureHeaders`
call to begin with — hence the 9-vs-10 call-site split in the matrix above.

## Consequences

**Positive**

- Host CORS, HTTPS redirect, and response-header configuration is entirely host-controlled; CSL
  carries no origin, path, redirect-strategy, or header-content opinions.
- Hosts needing distinct per-chain JWT authority mapping (e.g. multiple API versions) can express
  that without CSL changes on their side beyond passing the parameter, with zero behaviour change
  for every existing caller.
- All three `ObjectProvider`-collected hooks compose cleanly with `@Order` when multiple customizers
  are registered, and `@ConditionalOnMissingBean` lets a host override the CORS default without
  touching CSL configuration classes.
- The `Converter<Jwt, Authentication>` → `Converter<Jwt, AbstractAuthenticationToken>` adapter that
  every host previously hand-wrote is now centralised in CSL.
- One `SecurityHeadersCustomizer` interface instead of two identical ones — smaller public API to
  document and maintain long term.

**Negative / accepted trade-offs**

- A host-provided `CorsConfigurationSource` affects the catch-all deny-all chain: preflight `OPTIONS`
  requests for unmatched paths now return a CORS 200 instead of a 404. This is the correct behaviour
  for CORS preflight (the browser expects a 200; the actual request will still 404), but it is a
  visible behaviour change for hosts that don't currently use CORS.
- `NoOpCorsConfigurationSource` still technically accepts `registerCorsConfiguration` calls; any
  mappings registered on it are silently ignored because `applyCorsConfiguration` keys on the marker
  type, not on the registered mappings.
- There is no built-in ordering guarantee between a host's CSP logic and its other header logic — a
  host wanting that ordering expresses it itself (e.g. two `@Order`ed beans, or one bean doing both).
  This is a deliberate simplification: that separation was the main argument for keeping two header
  interfaces, and it didn't outweigh maintaining two byte-identical SPIs.
- `ScopedApiSecurityChainBuilder` now has two overloads per entry point instead of one for the JWT
  converter, growing the builder's public surface. Accepted because the alternative (a global
  customizer) cannot express the motivating multi-chain use case at all.
- Unlike the two `ObjectProvider`-discoverable hooks, the JWT-converter hook is not discoverable — a
  host must thread the converter through to the call site explicitly (typically via its own `@Bean`
  method parameter with `@Qualifier`), consistent with the existing `oidcDecoderSupplier` shape.
- A converter that returns an `Authentication` which is not an `AbstractAuthenticationToken` fails
  the request as a 401 (`InvalidBearerTokenException`) rather than at compile time — a runtime
  contract, not enforced by the type system, matching the constraint every host already lived with.
- **Last-writer-wins between the per-chain converter and `OidcResourceServerCustomizer`** (see
  above) — a host combining both hooks on the same chain should know that a customizer calling
  `jwtAuthenticationConverter(...)` overrides the per-chain converter, since customizers run after
  it is set.

## Alternatives Considered

- **Extend `OidcResourceServerCustomizer` and let hosts call `jwt.jwtAuthenticationConverter(...)`
  themselves from inside a customizer.** Rejected — that hook is a shared, `@Order`-composed list
  applied to every chain, not parameterized by chain identity. A host could technically call the
  converter setter from inside a customizer today, but there is no way to select "only this specific
  chain gets this converter" — every registered customizer runs on every chain. This is the sharpest
  illustration of why the per-chain-identity problem in the matrix above cannot be solved by the
  shared-customizer shape.
- **Per-invocation parameter for `SecurityHeadersCustomizer`, mirroring the JWT-converter hook.**
  Rejected — CSP and header behaviour is not genuinely per-chain-instance the way JWT authority
  mapping can be (multiple API versions needing different converters simultaneously); one customizer
  bean applied uniformly, with route-based logic living inside the host's own `HeaderWriter`, is
  sufficient and matches the existing `HttpsRedirectCustomizer` precedent more closely.

Consolidates records previously numbered 0036, 0037 (see git history).
