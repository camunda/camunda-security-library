---
status: Accepted
---

# ADR-0032: Scheduled refresh-ahead JWKS caching and realistic HTTP timeouts

**Deciders**: Ben Sheppard

## Status

Accepted

## Context

[ADR-0006](0006-multi-idp-oidc-configuration.md) records that every Nimbus `JWKSource` CSL builds
— for the single-URI path and for each primary/additional URI inside `CompositeJWKSource` — is
constructed via `JWKSourceBuilder.create(url).refreshAheadCache(false).rateLimited(false).cache(true).build()`,
deliberately mirroring the settings Spring's own `NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder` uses
internally. With `refreshAheadCache(false)`, a JWK Set refresh is only triggered by an incoming
decode request that finds the cache expired (or sees an unrecognized `kid`), and that request
blocks on a single synchronous HTTP fetch using Nimbus's own default connect/read timeouts — 500ms
each (`JWKSourceBuilder.DEFAULT_HTTP_CONNECT_TIMEOUT` / `DEFAULT_HTTP_READ_TIMEOUT`).

500ms is tight for a real external IdP under ordinary load, not just during an outage. When the
cache expires, every concurrently active request finds it expired at once; one of them wins
Nimbus's internal lock and performs the fetch, and the rest block on that lock for up to the cache
refresh timeout (15s, `JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT`). If the IdP's JWKS endpoint
takes longer than 500ms to respond, the lock-holder's fetch fails, releases the lock, and the next
waiting thread retries the same doomed fetch — repeating until the 15s budget elapses, at which
point `JWKSetUnavailableException: Timeout while waiting for cache refresh (15000ms exceeded)`
surfaces as `AuthenticationServiceException` for every request that was waiting. Because the
`JwtDecoder` is a single per-JVM singleton, this fails every concurrently active authenticated
request on that instance at once — see
[camunda-security-library#612](https://github.com/camunda/camunda-security-library/issues/612).

What caching and timeout configuration lets a single slow or briefly unreachable JWKS endpoint fail
without synchronizing authentication failures across every concurrent request on a JVM instance,
while still bounding how long a signing-key set can go unrefreshed?

## Decision

`JWSKeySelectorFactory#createJWKSource(URL)` — the single construction point for every Nimbus
`JWKSource` CSL builds, on both the single-URI path and inside `CompositeJWKSource` — now builds
each source with:

- **`refreshAheadCache(30_000, true)`** — the cache is refreshed roughly 30 seconds ahead of its
  expiry, on Nimbus's own dedicated background executor, scheduled regardless of whether a request
  arrives (`scheduled = true`). Live decode requests read the already-warm cache; they are not
  blocked by the refresh.
- **`cache(300_000, 15_000)`** — an explicit 5-minute cache time-to-live and 15-second refresh
  timeout. This is the staleness bound: if the background refresh cannot keep the cache current
  for a full 5 minutes (a sustained IdP outage outlasting the refresh-ahead window), the next
  decode request forces a synchronous fetch bounded by the unchanged 15-second refresh timeout,
  rather than serving the expired set indefinitely. An unrecognized `kid` forces the same bounded
  synchronous fetch immediately, independent of TTL, through Nimbus's existing
  `JWKSetCacheRefreshEvaluator` — unchanged by this ADR, and covered by a dedicated test (see
  `JWSKeySelectorFactoryTest#shouldForceAFreshFetchWhenKidIsUnknownEvenWithinTtl`).
- **`rateLimited(false)`** — unchanged from ADR-0006. Multi-instance refresh coordination across a
  fleet is a separate, more open-ended design question (see "Alternatives Considered" below), not
  resolved here.
- **A custom `DefaultResourceRetriever(3_000, 3_000, JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT)`** in
  place of the retriever `JWKSourceBuilder.create(url)` builds internally, raising the HTTP connect
  and read timeouts from Nimbus's 500ms default to 3 seconds each.

Each of the five numeric values above is exposed as an overridable `protected` getter on
`JWSKeySelectorFactory` (`getHttpConnectTimeoutMillis()`, `getHttpReadTimeoutMillis()`,
`getCacheTimeToLiveMillis()`, `getCacheRefreshTimeoutMillis()`, `getRefreshAheadTimeMillis()`), so a
host needing different values registers a `@Bean JWSKeySelectorFactory` subclass rather than
reimplementing `createJWKSource` from scratch.

These settings apply uniformly everywhere `JWSKeySelectorFactory` builds a `JWKSource` — the
single-URI path and every source composed inside `CompositeJWKSource` — so behavior is consistent
whether or not `additional-jwk-set-uris` is configured.

**A direct consequence of enabling `refreshAheadCache`:** building a `JWKSource` now starts a live
background thread pair *at construction time*, not at first use. `IssuerAwareJWSKeySelector` (the
multi-issuer key selector used whenever more than one OIDC provider is configured) previously built
a candidate selector for a never-before-seen issuer outside any lock and discarded whichever one
lost a `ConcurrentHashMap#putIfAbsent` race — harmless when a discarded candidate held no live
resources, but it would now orphan a background thread pair per losing race, permanently, for the
life of the JVM. `IssuerAwareJWSKeySelector#keySelectorFor` is changed in the same commit series to
use `ConcurrentHashMap#computeIfAbsent`, which single-flights construction so only the one selector
that is actually kept is ever built.

### Why these particular boundaries

- **Scheduled refresh-ahead (`scheduled = true`), not request-triggered.** Nimbus's refresh-ahead
  also supports a mode where the ahead-of-expiry refresh is only kicked off by an incoming request
  that happens to land inside the refresh-ahead window. Under genuinely low traffic against a given
  provider, that still risks the TTL lapsing with no request around to trigger the refresh —
  reintroducing exactly the blocking behavior this ADR removes, and doing so for the
  hardest-to-notice case (a rarely used provider). Scheduling on Nimbus's own background executor
  removes the dependency on request timing entirely, at the cost of one extra background thread
  pair per configured JWKS source — see "Negative / accepted trade-offs" for how that cost scales.
- **3 seconds, not Nimbus's 500ms default or a much larger number.** Chosen to comfortably exceed
  realistic network/IdP response-time jitter (typically tens to low hundreds of milliseconds) while
  still failing fast enough that a genuinely unreachable IdP is reported within a few seconds rather
  than tying up decode threads for tens of seconds. Hosts with different latency characteristics
  override the getters.
- **5-minute TTL / 15-second refresh timeout, left at Nimbus's own defaults rather than widened
  further.** Widening the TTL would extend how long a key could stay trusted after an IdP revokes
  it; the 15-second refresh timeout already bounds the worst case for a single synchronous fetch,
  and it is the refresh-ahead *scheduling* above — not this value — that removes live-request
  blocking in the common case. Making both values explicit constants (rather than leaving them as
  implicit Nimbus defaults) documents the staleness bound instead of leaving it accidental.
- **`rateLimited` left disabled.** Enabling it changes retrieval cadence across every instance in a
  fleet simultaneously — a multi-instance coordination problem (queue vs. back off) distinct from
  this ADR's single-instance blocking behavior. Bundling it here would couple two independent design
  decisions; see "Alternatives Considered".
- **`computeIfAbsent` over a double-checked-locking rewrite.** `ConcurrentHashMap#computeIfAbsent`
  already gives the single-flight-per-key guarantee needed here, does not cache a thrown exception
  (so a failed resolution is retried on the next request, matching prior behavior), and does not
  serialize resolution of *different* issuers against each other (the mapping function only holds
  the map's internal per-bin synchronization, not a map-wide lock) — preserving the original code's
  explicit intent that one issuer's slow discovery must not hold up another issuer's tokens.

### Default implementations and override boundaries

| Concern | Default | Override path |
|---|---|---|
| HTTP connect / read timeout | 3s / 3s (`DefaultResourceRetriever`) | Host registers `@Bean JWSKeySelectorFactory` overriding `getHttpConnectTimeoutMillis()` / `getHttpReadTimeoutMillis()` |
| Cache TTL / refresh timeout | 300,000ms / 15,000ms | Override `getCacheTimeToLiveMillis()` / `getCacheRefreshTimeoutMillis()` |
| Refresh-ahead time / scheduling | 30,000ms, scheduled in the background | Override `getRefreshAheadTimeMillis()`, or override `createJWKSource(URL)` directly for `scheduled = false` |
| Rate limiting | Disabled | Override `createJWKSource(URL)` |
| Per-issuer selector construction | Single-flighted via `computeIfAbsent` | Host registers `@Bean JWSKeySelectorFactory` or a custom multi-issuer key selector entirely |

## Consequences

**Positive**

- A JWKS endpoint that is slow by up to ~3 seconds no longer causes synchronized authentication
  failures: the background refresh keeps the cache warm ahead of expiry, so live decode requests
  read it rather than waiting on the refresh.
- The maximum staleness of a trusted key set is now an explicit, documented 5-minute bound rather
  than an implicit Nimbus default, and an unrecognized `kid` still forces a bounded fresh fetch
  rather than being evaluated against a silently-stale set — both are covered by dedicated tests.
- No new dependency — built entirely from the existing `JWKSourceBuilder` / `DefaultResourceRetriever`
  surface already on the classpath via `nimbus-jose-jwt`.

**Negative / accepted trade-offs**

- Each configured JWKS source now owns a background scheduled-refresh thread pair for the lifetime
  of the process. This scales with **both** the number of configured JWKS URIs (primary +
  additional, per issuer) **and** the number of independently-built decoder scopes: a host using the
  `Scoped*` per-physical-tenant chain pattern (`ScopedJwtDecoderFactory`) builds one such set of
  sources *per scope*, so a deployment with many scopes multiplies the thread count by scope count
  on top of the per-issuer/per-URI multiplier. This ADR accepts that cost under the explicit
  assumption that decoders are built once per process (or once per scope, for the lifetime of that
  scope) and are not repeatedly rebuilt — the codebase has no `.close()`/`@PreDestroy` path for any
  `JwtDecoder` or `JWKSource` today, so a decoder or scope that *is* rebuilt at runtime (a config
  reload, a scope recreated on topology change) currently leaks its predecessor's background threads
  permanently. Wiring a close/disposal path for rebuilt decoders is tracked as a follow-up, not
  resolved here — today's codebase already does not rebuild decoders at runtime, only once at
  startup (or once per scope's first use, via `DeferredJwtDecoder`), so the gap is latent rather than
  currently triggered.
- `DeferredJwtDecoder`'s retry-on-failure path (used for both the single- and multi-provider case)
  can itself cause more than one JWKS source to be built if an attempt builds some sources
  successfully before a later step (e.g. validator construction) fails and the whole attempt is
  retried on the next decode call — each retried attempt builds fresh sources, and nothing closes
  the discarded ones from the failed attempt. This is the same latent gap as above (no close path
  for a never-kept `JWKSource`), not a new one introduced by this ADR, but this ADR's background
  threads make that latent gap newly visible/costly where before it was free. Tracked as the same
  follow-up.
- 3 seconds is still finite: an IdP outage exceeding it still fails the in-flight request. This ADR
  narrows the blocking window to realistic latency — it does not eliminate failures from genuine
  unavailability, and it does not attempt `rateLimited(true)` multi-instance coordination (tracked
  as a possible follow-up, not resolved here).
- A key that should be revoked urgently can remain trusted for up to the now-explicit 5-minute TTL
  plus however long the IdP itself stays unreachable beyond that. This is unchanged from the prior
  implicit behavior — ADR-0006's defaults already had this property — but is now a documented,
  deliberate bound rather than an accident of Nimbus's defaults.

## Alternatives Considered

- **Leave `refreshAheadCache(false)` and only raise the HTTP timeouts.** Rejected — still lets
  every concurrent request block directly on the IdP's response time on each cache-miss or
  `kid`-miss; only shifts the blocking threshold from 500ms to 3s, it does not remove the
  "synchronized burst" failure mode #612 describes.
- **Request-triggered refresh-ahead (`scheduled = false`).** Rejected — a JWKS source serving
  near-zero traffic between expiries would never have its ahead-of-expiry refresh triggered,
  reintroducing the exact blocking behavior this ADR removes, for the provider it is hardest to
  notice on.
- **Enable `rateLimited(true)` alongside this change.** Rejected for this ADR — coordinating
  refresh cadence across independently-scaled instances is a genuinely separate design question
  (raised explicitly as a follow-up in #612's own "Additional Context"); bundling it here risks
  shaping this decision around constraints that belong to that separate problem.
- **Widen the cache TTL further to reduce refresh frequency.** Rejected — trades key-revocation
  responsiveness for a benefit (fewer refreshes) that scheduled refresh-ahead already delivers
  without that cost.
- **Leave `IssuerAwareJWSKeySelector`'s build-then-discard race as is.** Rejected — once
  `refreshAheadCache` is enabled, a discarded candidate is no longer free; it is a permanently
  orphaned background thread pair. `computeIfAbsent` removes the race with no behavioral change
  visible to callers (same single-entry-per-issuer outcome, same non-caching of failures).
