---
status: Accepted
---

# ADR-0037: Security-headers customizer hook (covers CSP)

**Deciders**: Ben Sheppard, Sebastian Bathke (megglos)

## Status

Accepted

## Context

`SecurityFilterChainSupport.setupSecureHeaders(...)` applies Content-Security-Policy and the rest
of CSL's response headers as a fixed, static set driven entirely by `camunda.security.http-headers.*`
properties, uniformly across the whole chain. There was no way for a host to generate a per-request
CSP nonce, vary the policy or headers by route, or add a header CSL doesn't know about.

This gap was surfaced while scoping camunda/camunda-hub's P7 phase-swap
(camunda-security-library#308): Hub's `WebSecurityConfiguration` builds a fresh CSP nonce per
request and varies `frame-ancestors`/`X-Frame-Options` by whether a route is embeddable, and emits
`Origin-Agent-Cluster`, `X-DNS-Prefetch-Control`, and `X-Download-Options` — none of which CSL's
static configuration can express. Tracked as #538 (CSP) and #539 (headers) — two separate issues,
but see Decision below for why they resolve to one hook.

What SPI shape lets a host contribute per-request CSP nonces and route-varying security headers
without CSL hard-coding a nonce strategy or a fixed header set?

## Decision

Add one new hook — `SecurityHeadersCustomizer` — following the exact existing
`HttpsRedirectCustomizer` pattern (see [ADR-0034](0034-cors-and-https-redirect-host-hooks.md)): a
`@FunctionalInterface` receiving full `HttpSecurity`, collected via `ObjectProvider`, applied in
`@Order` order, no-op when absent.

This closes both #538 (CSP) and #539 (headers) with a single interface: CSP is, mechanically, just
another response header. A host implements nonce generation or per-route header variation entirely
*inside* its own bean (typically a custom `HeaderWriter` added via `http.headers(headers ->
headers.addHeaderWriter(...))`), the same way `HttpsRedirectCustomizer` implementations add their
own filter. The hook itself doesn't need to be scope-parameterized because the host's own
`HeaderWriter`/filter already runs per-request and can inspect the request to decide what to do per
route.

The hook is applied immediately after `setupSecureHeaders(...)` at every one of its 9 call sites —
the same content-serving chains `HttpsRedirectCustomizer` and CORS apply to, minus the catch-all
deny-all chain (`protectedUnhandledPathsSecurityFilterChain`), which serves no content and has no
`setupSecureHeaders` call today.

### Revision note

An earlier draft of this ADR proposed two separate interfaces — `CspCustomizer` and
`SecurityHeadersCustomizer` — reasoning that CSP and other headers are "conceptually distinct
concerns for adopters." Review feedback (megglos) correctly challenged this: the two interfaces
were byte-for-byte identical (`void customize(HttpSecurity)`), applied back-to-back at all 9 sites
in the same fixed order, and registering one or the other did exactly the same thing. The only
actual distinction was naming intent, which doesn't justify a second public SPI surface that would
need to be supported indefinitely. This revision merges them into the single hook described above.

## Consequences

**Positive**

- Hosts needing dynamic CSP nonces, per-route header variation, or additional headers can express
  that without CSL changes, using the exact same pattern already familiar from
  `HttpsRedirectCustomizer`.
- Zero behavior change for hosts that register no customizer bean.
- Coexists with CSL's static header configuration rather than replacing it — a host's custom
  `HeaderWriter` is additive via `addHeaderWriter`, so `camunda.security.http-headers.*` properties
  keep working for hosts that don't need dynamic behavior.
- One SPI surface instead of two identical ones — smaller public API to document and maintain long
  term.

**Negative / accepted trade-offs**

- The hook gives the host full `HttpSecurity` access rather than a narrower CSP-specific or
  header-specific API — accepted for consistency with `HttpsRedirectCustomizer`'s established
  precedent; a narrower API would need CSL to anticipate every possible header-writer shape a host
  might need, which ADR-0034 already rejected for the HTTPS-redirect case for the same reason.
- A host that wants ordering guarantees between its CSP logic and its other header logic must
  express that itself (e.g. two `@Order`ed beans, or one bean doing both) — there is no built-in
  "CSP group runs before headers group" separation. This is a deliberate simplification: that
  separation was the main argument for two hooks, and it doesn't outweigh maintaining two identical
  interfaces.

## Alternatives Considered

- **Two hooks — `CspCustomizer` and `SecurityHeadersCustomizer`.** This was the original decision
  in this ADR's first draft. Rejected on revision — see "Revision note" above.
- **Extend the static `HeaderConfiguration`/properties model with nonce support baked in.**
  Rejected — nonce generation strategy, cookie/attribute propagation to templates, and per-route
  exemptions are all host-specific decisions CSL has no opinion on, the same reasoning ADR-0034
  applied to HTTPS-redirect strategy.
- **Per-invocation parameter, like the `JwtAuthenticationConverter` hook (camunda-security-library#537).**
  Rejected — CSP and header behavior is not genuinely per-chain-instance the way JWT authority
  mapping can be (multiple API versions needing different converters simultaneously); one
  customizer bean applied uniformly, with route-based logic living inside the host's own
  `HeaderWriter`, is sufficient and matches the existing `HttpsRedirectCustomizer` precedent more
  closely.
