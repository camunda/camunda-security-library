---
status: Accepted
---

# ADR-0032: Scheduled refresh-ahead JWKS caching and realistic HTTP timeouts

**Deciders**: Ben Sheppard

## Status

Accepted. Partially supersedes [ADR-0006](0006-multi-idp-oidc-configuration.md) — its `JWKSource` construction settings only, see [Supersedes](#supersedes). Every other decision of that record — the multi-IdP configuration model, `CompositeJWKSource`, the per-issuer key selector — stays in force.

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

- **`refreshAheadCache(30_000, <failure listener>, <executor>, false, <scheduledExecutor>, false)`** —
  the cache is refreshed in the background ahead of its expiry, scheduled regardless of whether a
  request arrives. Nimbus dispatches the refresh at `TTL − refresh-ahead − refresh timeout` after a
  load — with the defaults, 4m15s into a 5m TTL, i.e. 45 seconds before expiry — which leaves the
  15-second refresh timeout as margin before the 30-second refresh-ahead window opens. (Supplying a non-null
  scheduled executor is what sets Nimbus's `scheduled = true`.) Live decode requests read the
  already-warm cache; they are not blocked by the refresh. A failed refresh is logged at `WARN` with
  the JWK Set URI through the listener, because Nimbus otherwise swallows it and an IdP outage would
  stay invisible until the cache expired. Both executors are built here and shared by every source, rather than
  left to the shorter `refreshAheadCache(long, boolean)` overload, because Nimbus's own defaults
  are **non-daemon** `Executors.newSingleThread*` pools created per source: since nothing in CSL
  closes a `JWKSource`, a non-daemon refresh thread would outlive a host's Spring context and stop
  its JVM from exiting on shutdown. The scheduled task only dispatches the fetch, so one daemon
  scheduler thread (`csl-jwks-refresh-scheduler`) serves all sources, and the blocking fetches run
  on a shared virtual-thread-per-task executor (`csl-jwks-refresh-fetch-<n>`; virtual threads are
  always daemon). The footprint therefore does not grow with the number of issuers. Because the
  executors are shared, both `shutdownOnClose` flags are `false`.
- **`cache(300_000, 15_000)`** — an explicit 5-minute cache time-to-live and 15-second refresh
  timeout. This is the staleness bound: if the background refresh cannot keep the cache current
  for a full 5 minutes (a sustained IdP outage outlasting the refresh-ahead window), the next
  decode request forces a synchronous fetch, bounded by the 3-second HTTP timeouts per URI (the
  15-second refresh timeout is only how long *other* callers wait on the lock while that fetch runs),
  rather than serving the expired set indefinitely. An unrecognized `kid` forces the same bounded
  synchronous fetch immediately, independent of TTL, through Nimbus's existing
  `JWKSetCacheRefreshEvaluator` — unchanged by this ADR, and covered by a dedicated test (see
  `JWSKeySelectorFactoryTest#shouldForceAFreshFetchWhenKidIsUnknownEvenWithinTtl`).
- **`rateLimited(false)`** — unchanged from ADR-0006. Nimbus's `RateLimitedJWKSetSource` is a
  per-process, in-JVM cap on how often a single `JWKSource` instance re-fetches ("limits the number
  of requests in a time period … intended to guard against frequent, potentially costly, downstream
  calls", per its own Javadoc) — not a fleet-coordination mechanism. Whether to enable it is left
  out of scope for this decision because #612 itself carves it out as "a separate, more open-ended
  design question … worth a follow-up discussion rather than blocking this issue's closure". The
  cost of deferring it is stated explicitly under "Negative / accepted trade-offs".
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

**When the background threads actually appear.** `JWKSourceBuilder#build()` performs no I/O and
starts no thread: the shared executors above create their threads lazily, on first task
submission, and `RefreshAheadCachingJWKSetSource` only schedules its refresh *after* the
source has successfully served a first JWK Set load. A `JWKSource` that is constructed and then
never asked for a key is therefore inert and collectable.

That matters for `IssuerAwareJWSKeySelector` (the multi-issuer key selector used whenever more than
one OIDC provider is configured), which builds a candidate selector for a never-before-seen issuer
outside any lock and discards whichever one loses a `ConcurrentHashMap#putIfAbsent` race. Because
the losers' sources never fetch — every racing thread goes on to use the *winner's* selector — they
schedule nothing and leak nothing, so that lock-free pattern is kept deliberately. Serialising
construction instead (e.g. via `computeIfAbsent`) would hold one request thread per waiter for the
full provider-discovery timeout whenever resolution of a new issuer *fails*, turning a parallel
burst of N failures into N sequential ones — the very shape of request pile-up #612 exists to
remove. The same reasoning covers `DeferredJwtDecoder`'s retry path: a source built by an attempt
that is later abandoned costs nothing as long as it never served a request.

### Why these particular boundaries

- **Scheduled refresh-ahead (`scheduled = true`), not request-triggered.** Nimbus's refresh-ahead
  also supports a mode where the ahead-of-expiry refresh is only kicked off by an incoming request
  that happens to land inside the refresh-ahead window. Under genuinely low traffic against a given
  provider, that still risks the TTL lapsing with no request around to trigger the refresh —
  reintroducing exactly the blocking behavior this ADR removes, and doing so for the
  hardest-to-notice case (a rarely used provider). Scheduling in the background removes the
  dependency on request timing entirely, at the cost of recurring background fetches per actively
  used JWKS source — see "Negative / accepted trade-offs" for how that cost scales.
- **3 seconds, not Nimbus's 500ms default or a much larger number.** Chosen to comfortably exceed
  realistic network/IdP response-time jitter (typically tens to low hundreds of milliseconds) while
  still failing fast enough that a genuinely unreachable IdP is reported within a few seconds rather
  than tying up decode threads for tens of seconds. Hosts with different latency characteristics
  override the getters.
- **5-minute TTL / 15-second refresh timeout, left at Nimbus's own defaults rather than widened
  further.** Widening the TTL would extend how long a key could stay trusted after an IdP revokes
  it; the 3-second HTTP timeouts already bound a single synchronous fetch (the 15-second refresh
  timeout is the lock-wait limit for callers queued behind it), and it is the refresh-ahead *scheduling* above — not this value — that removes live-request
  blocking in the common case. Making both values explicit constants (rather than leaving them as
  implicit Nimbus defaults) documents the staleness bound instead of leaving it accidental.
- **`rateLimited` left disabled.** Enabling it caps how often one instance re-fetches, which is a
  worthwhile mitigation for the `kid`-miss cost described below, but choosing the interval interacts
  with key-rotation responsiveness and with how a fleet of instances behaves in aggregate. #612
  explicitly scopes that out of this change; see "Alternatives Considered".
- **Daemon executors supplied explicitly, rather than Nimbus's defaults.** Nimbus's convenience
  overload creates non-daemon single-thread pools per source, and CSL has no `.close()`/`@PreDestroy` path for
  a `JWKSource`, so such a thread would survive context shutdown and keep a host JVM from exiting.
  Surefire cannot detect this (it exits its fork explicitly), so a dedicated test asserts the
  scheduler thread is a daemon thread (the fetches run on virtual threads, always daemon).

### Default implementations and override boundaries

| Concern | Default | Override path |
|---|---|---|
| HTTP connect / read timeout | 3s / 3s (`DefaultResourceRetriever`) | Host registers `@Bean JWSKeySelectorFactory` overriding `getHttpConnectTimeoutMillis()` / `getHttpReadTimeoutMillis()` |
| Cache TTL / refresh timeout | 300,000ms / 15,000ms | Override `getCacheTimeToLiveMillis()` / `getCacheRefreshTimeoutMillis()` |
| Refresh-ahead time / scheduling | 30,000ms, scheduled in the background on one shared daemon scheduler thread, fetching on shared virtual threads | Override `getRefreshAheadTimeMillis()`, or override `createJWKSource(URL)` directly for `scheduled = false` or different executors |
| Rate limiting | Disabled | Override `createJWKSource(URL)` |

Any override of the three cache getters must keep `getRefreshAheadTimeMillis() +
getCacheRefreshTimeoutMillis() < getCacheTimeToLiveMillis()`, strictly. Nimbus rejects a sum above
the TTL with an `IllegalArgumentException` at bean creation, but accepts equality and then computes
a zero scheduling delay, which it does not schedule — silently reverting to request-driven refresh.
And the closer that sum gets to the TTL, the more the background refresh cadence collapses towards
continuously polling the IdP.

## Supersedes

| Superseded statement | Record | Now |
|---|---|---|
| Every `JWKSource` is built as `JWKSourceBuilder.create(url).refreshAheadCache(false).rateLimited(false).cache(true).build()`, mirroring Spring's `NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder` | ADR-0006 | Refresh-ahead caching is enabled and scheduled on shared daemon executors, failures logged, cache TTL and refresh timeout are set explicitly, and a `DefaultResourceRetriever` with 3s HTTP timeouts replaces Nimbus's 500ms default; `rateLimited(false)` is unchanged |

## Consequences

**Positive**

- A JWKS endpoint that is slow by up to ~3 seconds no longer causes synchronized authentication
  failures: the background refresh keeps the cache warm ahead of expiry, so live decode requests
  read it rather than waiting on the refresh. That the refresh really is independent of request
  timing is covered by a test that refreshes a source receiving no traffic at all
  (`JWSKeySelectorFactoryTest#shouldRefreshTheCachedJwkSetInTheBackgroundWithoutAnyFurtherRequests`).
- The maximum staleness of a trusted key set is now an explicit, documented 5-minute bound rather
  than an implicit Nimbus default, and an unrecognized `kid` still forces a bounded fresh fetch
  rather than being evaluated against a silently-stale set — both are covered by dedicated tests.
- No new dependency — built entirely from the existing `JWKSourceBuilder` / `DefaultResourceRetriever`
  surface already on the classpath via `nimbus-jose-jwt`.

**Negative / accepted trade-offs**

- Every *actively used* JWKS source now keeps re-scheduling its own background refresh for the
  lifetime of the process, and nothing closes it: CSL has no `.close()`/`@PreDestroy` path for a
  `JwtDecoder` or a `JWKSource`. The executors are shared and daemon, so the cost is not a thread
  per source and does not block JVM shutdown — it is one scheduled fetch of the IdP's JWKS endpoint
  roughly every 4m15s per source, forever. A decoder or scope that is *rebuilt* at runtime (a config
  reload, a scope recreated on topology change) would leave its predecessor's source refreshing
  until the process ends. The count scales with **both** the number of configured JWKS URIs
  (primary + additional, per issuer) **and** the number of independently-built decoder scopes: a
  host using the `Scoped*` per-physical-tenant chain pattern (`ScopedJwtDecoderFactory`) builds one
  set of sources *per scope*. This ADR accepts that cost on the basis that decoders are built once
  per process (or once per scope's first use, via `DeferredJwtDecoder`) and are not rebuilt at
  runtime today, so the gap is latent. Wiring a disposal path is a follow-up, not resolved here.
  Sources that are built and then abandoned without ever serving a request — a `putIfAbsent` race
  loser, a `DeferredJwtDecoder` attempt that fails at a later step — cost nothing, as explained
  under "Decision".
- An unrecognized `kid` forces an immediate synchronous fetch independent of TTL (Nimbus's `noMatch`
  refresh evaluator), and with `rateLimited(false)` nothing caps how often that happens. Raising the
  HTTP timeouts therefore also raises what a single such request can cost: up to 3s connect + 3s
  read per JWKS URI — multiplied by the number of URIs when `additional-jwk-set-uris` is configured,
  and up to the 15s refresh timeout under lock contention — where Nimbus's 500ms default bounded it
  much sooner. A caller presenting tokens with random `kid`s can thus tie up more decode-thread time
  per request than before. Accepted here because tokens still have to carry a configured issuer to
  reach this path at all, and because capping the cadence is exactly the `rateLimited(true)`
  discussion #612 defers.
- 3 seconds is still finite: an IdP outage exceeding it still fails the in-flight request. This ADR
  narrows the blocking window to realistic latency — it does not eliminate failures from genuine
  unavailability.
- A key that should be revoked urgently can remain trusted for up to the now-explicit 5-minute TTL.
  After that the source forces a refresh, and if the IdP is still unreachable decoding fails rather
  than continuing to trust the stale set (Nimbus's outage-tolerant mode is not enabled), so an
  outage does not extend the bound — it costs availability instead. The 5-minute bound is unchanged
  from the prior implicit behavior — ADR-0006's defaults already had it — but is now a documented,
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
- **Enable `rateLimited(true)` alongside this change.** Deferred, not rejected on the merits — it is
  the natural mitigation for the `kid`-miss cost listed above. #612's own "Additional Context" raises
  it explicitly as "a separate, more open-ended design question … worth a follow-up discussion
  rather than blocking this issue's closure", and picking an interval needs its own analysis
  (Nimbus's default allows two fetches per interval precisely so a key rotation can still trigger a
  refresh), so it is left to that follow-up.
- **Widen the cache TTL further to reduce refresh frequency.** Rejected — trades key-revocation
  responsiveness for a benefit (fewer refreshes) that scheduled refresh-ahead already delivers
  without that cost.
- **Single-flight `IssuerAwareJWSKeySelector`'s per-issuer construction via `computeIfAbsent`.**
  Rejected — the leak it would prevent does not exist (a discarded candidate never fetches and so
  never starts a thread, see "Decision"), while the cost is real: `computeIfAbsent` holds the map
  bin for the whole mapping function, so repeated *failing* resolutions of one issuer would run one
  after another, holding request *i* for roughly *i* × the discovery timeout instead of failing N
  requests in parallel in one timeout. The lock-free build-then-discard pattern is kept, which also
  keeps it consistent with the same deliberate choice already documented in
  `ScopedClientRegistrationFactory` and `CamundaOidcAuthorizationRequestResolver`.
