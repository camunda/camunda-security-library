---
status: Accepted
---

# ADR-0034: CORS and HTTPS redirect hooks for host applications

**Deciders**: Ben Sheppard, Sebastian Bathke (megglos)

## Status

Accepted

## Context

CSL previously hard-coded `.cors(AbstractHttpConfigurer::disable)` on every security filter chain.
Host applications had no way to enable CORS or add an HTTPS redirect filter — both behaviours vary
by deployment environment and cannot be decided by the library.

[ADR-0006](0006-central-security-filter-chains.md) centralised filter chain construction in CSL but
deferred host-specific wiring. CORS configuration and HTTPS redirect strategy are the first two
cases of that deferred work now being resolved.

Two questions this ADR answers:

1. How should a host enable CORS without CSL hard-coding a `/**` mapping or knowing the host's
   allowed origins?
2. How should a host insert an HTTPS redirect filter without duplicating filter chain construction
   or bypassing CSL's security constraints?

## Decision

### CORS hook — `CorsConfigurationSource` bean override

`CorsBeansConfiguration` provides a `@ConditionalOnMissingBean CorsConfigurationSource` default.
The default is an instance of `NoOpCorsConfigurationSource`, a dedicated marker subtype of
`UrlBasedCorsConfigurationSource` with no registered mappings.

`SecurityFilterChainSupport.applyCorsConfiguration` checks for the marker via `instanceof
NoOpCorsConfigurationSource`:

- If the marker is present (CSL default): disables CORS via `.cors(disable)`, preserving the
  previous behaviour.
- Otherwise (host bean): enables CORS and wires the host source into the chain.

A host enables CORS by registering any `CorsConfigurationSource` bean. `@ConditionalOnMissingBean`
on the CSL default ensures it backs off automatically.

The marker subtype (rather than checking for an empty `UrlBasedCorsConfigurationSource`) is
intentional: a host that provides its own initially-empty `UrlBasedCorsConfigurationSource` and
populates it after context refresh would otherwise be silently ignored by an emptiness check.

### HTTPS redirect hook — `HttpsRedirectCustomizer` SPI

`HttpsRedirectCustomizer` is a `@FunctionalInterface` that receives `HttpSecurity`. Hosts register a
bean of this type to insert a redirect filter into every CSL filter chain.

`SecurityFilterChainSupport.applyHttpsRedirectCustomizers` collects registered beans in
`@Order` order and calls `customize(http)` on each during chain construction. No bean present means
no redirect — CSL's default is to leave HTTP→HTTPS policy to the host's infrastructure layer (load
balancer, ingress).

This follows the established `OidcResourceServerCustomizer` pattern (see
[ADR-0006](0006-central-security-filter-chains.md)) and requires no CSL changes when a host adds or
removes a redirect strategy.

### Applied to all chains, including the catch-all deny-all chain

Both hooks are applied to every filter chain, including `protectedUnhandledPathsSecurityFilterChain`
(the lowest-priority `/**` deny-all chain). This is intentional: a host-provided
`CorsConfigurationSource` with a broad `/**` mapping must handle preflight OPTIONS requests even for
paths that don't match any other chain; restricting hooks to "content-serving" chains would silently
miss those preflight requests.

## Consequences

**Positive**

- Host CORS and HTTPS redirect configuration is entirely host-controlled; CSL carries no
  origin, path, or redirect-strategy opinions.
- The no-op default preserves the previous behaviour when a host provides no CORS bean.
- The `HttpsRedirectCustomizer` SPI composes cleanly with `@Order` when multiple customizers
  are registered.
- `@ConditionalOnMissingBean` ensures a host can override the CORS default without touching
  CSL configuration classes.

**Negative / accepted trade-offs**

- A host-provided `CorsConfigurationSource` affects the catch-all deny-all chain. Preflight
  OPTIONS requests for unmatched paths return a CORS 200 instead of a 404. This is the correct
  behaviour for CORS preflight (the browser expects a 200; the actual request will still 404), but
  it is a visible behaviour change for hosts that do not currently use CORS.
- The `NoOpCorsConfigurationSource` marker subtype extends `UrlBasedCorsConfigurationSource`,
  which means it technically accepts `registerCorsConfiguration` calls; callers that register
  mappings on it would still have CORS disabled because `applyCorsConfiguration` keys on the marker
  type. The Javadoc on `NoOpCorsConfigurationSource` documents this.

## Alternatives Considered

- **`@ConditionalOnProperty` CORS toggle.** Rejected — the host controls which origins are
  allowed, not just whether CORS is enabled. A property toggle would still require the host to
  supply the origin list through a different mechanism.
- **Emptiness check on `UrlBasedCorsConfigurationSource`** (disable when no mappings registered).
  Rejected — a host that starts with an empty source and populates it after context startup would
  be silently ignored. The dedicated marker type is unambiguous.
- **Separate `HttpsRedirectFilter` CSL default.** Rejected — CSL has no opinion on which redirect
  strategy, excluded paths, or response code a host wants. The SPI delegates the entire decision to
  the host.
