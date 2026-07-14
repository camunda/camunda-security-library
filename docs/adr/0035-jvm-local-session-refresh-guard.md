---
status: Accepted
---

# ADR-0035: JVM-local, session-ID-keyed guard for authentication refresh dedup

**Deciders**: Sebastian Bathke, Joaquin Felici

## Status

Accepted

## Context

`HttpSessionBasedAuthenticationHolder` re-checks `AUTH_LAST_REFRESH` on every `get()` and, once the
configured `authentication-refresh-interval` has elapsed, refreshes the cached
`CamundaAuthentication` exactly once per session. `lockAndRefresh` enforces the "exactly once" part
with `synchronized (session)` — but that only serializes callers that hold the identical
`HttpSession` Java object.

That assumption broke once every CSL surface started resolving sessions through Spring Session
([ADR-0031](0031-explicit-default-session-filter-replaces-global-filter.md) removed the last path
that used the servlet container's native, per-ID-stable `HttpSession`). `request.getSession(false)`
now always goes through `SessionRepository.findById(id)`, and every `SessionRepository`
implementation in play returns a fresh object per call for the same underlying session id:

- CSL's own `WebSessionRepository` (persistent sessions, ADR-0017) calls
  `sessionStorePort::get`, which round-trips the host's storage and constructs a new `WebSession`
  each time ([`WebSessionRepository.java:67-74`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/session/WebSessionRepository.java#L67-L74)).
- Spring Session's own `MapSessionRepository` — the fallback used for the default surface when
  persistence is off (ADR-0031) — also returns `new MapSession(saved)`, a copy, on every
  `findById`.

So two concurrent requests against the same session id can each resolve a distinct `HttpSession`
instance, each observe an expired `AUTH_LAST_REFRESH`, and each pass the `synchronized (session)`
guard because they're synchronizing on different monitors. This reproduces reliably (see
[camunda-security-library#510](https://github.com/camunda/camunda-security-library/issues/510)) and
was masked in the host-side test only by timing luck.

Fixing this by making the guard operate on the session id instead of the `HttpSession` object is a
necessary but not sufficient fix on its own: each request's `HttpSession` is a **snapshot** fetched
by `findById` before any refresh logic runs, and Spring Session only writes attribute changes back
to the repository at end-of-request `save()`. A lock that only serializes *code execution* around a
stale, already-fetched snapshot does not stop a second thread from reading `AUTH_LAST_REFRESH` as
expired even after a first thread's refresh has logically "completed" inside the lock — the two
threads are looking at independent copies, not a shared source of truth.

A store-level compare-and-set on `SessionStorePort` (the direction floated in #510) was considered
and rejected — see Alternatives. The question this ADR answers: **what mechanism makes the refresh
dedup hold across independently-resolved `HttpSession` instances, for every `SessionRepository` CSL
can be configured with, without changing an outbound port every host adapter must implement?**

## Decision

`HttpSessionBasedAuthenticationHolder` gains a JVM-local, session-id-keyed guard that is the actual
source of truth for "has this session already been refreshed", independent of any single
`HttpSession` object's attribute snapshot:

- A `Cache<String, Instant> refreshClaims` (Caffeine — already a `spring-boot-starter` dependency
  used by `CachingOidcClaimsProvider`), keyed by `session.getId()`, value is the instant a refresh
  was last claimed for that session id.
- `lockAndRefresh` no longer synchronizes on the `HttpSession`. Instead it calls
  `refreshClaims.asMap().compute(sessionId, (id, lastClaimed) -> ...)`: inside the atomic `compute`,
  it decides whether `lastClaimed` (the JVM-local claim) is still valid by comparing it against the
  caller's own `observedLastRefresh` — the `AUTH_LAST_REFRESH` value that caller read and judged
  stale, not the (possibly stale) `session.getAttribute(LAST_REFRESH_ATTR)` re-read at `compute`
  time, and not elapsed wall-clock time against `authentication-refresh-interval` (see Addendum
  below). Only the caller whose `compute` sees a claim that
  predates its own observed staleness performs the refresh (`removeCamundaAuthenticationInSession` +
  `session.setAttribute(LAST_REFRESH_ATTR, now)`) and advances the claim; every other concurrent
  caller — regardless of which `HttpSession` object it holds — sees an already-current claim and
  skips.
- The cache is expiring (`expireAfterWrite`, a fixed 30-minute TTL, independent of the configured
  `authentication-refresh-interval`) so claims for sessions that are no longer active are evicted
  rather than accumulating forever. The TTL only bounds memory for dead sessions — it plays no role
  in correctness, because `lockAndRefresh` is only ever invoked after the outer
  `session.getAttribute(LAST_REFRESH_ATTR)` check has already decided a refresh is due; a cache miss
  inside `compute` is treated identically to "never claimed," which still lets exactly one caller
  win. A fixed TTL is deliberately not derived from `authentication-refresh-interval`: a shorter
  window would still be safe (it's already generous relative to the millisecond-scale race it
  guards against), and a longer configured interval must not inflate how long a dead session's
  entry lingers. No explicit removal on logout/invalidation is needed — a stale claim for a dead
  session is harmless (nothing reads it again) and ages out on its own.
- The cache is also size-bounded (`maximumSize`, 10,000 entries) as a memory-safety backstop
  against unbounded growth if a host runs far more concurrently-active sessions than expected.
  Unlike the TTL, this bound is *not* correctness-neutral: Caffeine can evict an entry for
  capacity reasons before its TTL elapses, including — in principle — an entry for a session that
  is still genuinely active. An eviction at that exact moment reopens the original race for that
  one session (a concurrent `compute` sees a miss and treats it as "never claimed"). See
  Consequences for why this is accepted rather than sized to be unreachable.
- `SessionStorePort`, `WebSessionRepository`, and `WebSession` are untouched. The guard lives
  entirely inside `HttpSessionBasedAuthenticationHolder`, which keeps working against the generic
  `jakarta.servlet.http.HttpSession` contract exactly as before.
- `refreshClaims` is a per-instance cache, so the holder must stay a **singleton** for the dedup to
  hold — a prototype- or request-scoped holder would give each request its own cache and reopen the
  race. The default `httpSessionBasedAuthenticationHolder` bean is singleton-scoped; the class
  javadoc states this as a precondition for any host that overrides the bean.
- The claim is advanced inside `compute` before the refresh side effects
  (`removeCamundaAuthenticationInSession` + `session.setAttribute`) run. If those side effects throw
  — for example the session was invalidated concurrently, which makes any further `HttpSession`
  access throw `IllegalStateException` — the claim is rolled back (removed, guarded so it only
  removes the value this call just wrote) before the exception propagates, so a subsequent request
  is not blocked from retrying the refresh for the remainder of the TTL.

### Why these particular boundaries

- **Keyed by session id, not by `HttpSession` identity.** Session id is stable across every
  `SessionRepository.findById` call for the same underlying session; the `HttpSession` object is
  not. This is the literal fix for the object-identity bug.
- **The cache, not the session attribute, is the authority during the decision.** Reading
  `lastClaimed` from `refreshClaims` inside `compute` — rather than re-reading
  `session.getAttribute(LAST_REFRESH_ATTR)` — is what closes the "stale snapshot" gap described in
  Context. The session attribute is still written (hosts and tests that inspect
  `AUTH_LAST_REFRESH` directly keep working, and it remains the persisted record of the last
  refresh), but it is no longer read as the decision input for concurrent callers.
- **JVM-local, not cross-instance.** This mirrors the scope of the guarantee the original
  `synchronized (session)` block always had — CSL has never deduplicated refreshes across multiple
  application instances / pods sharing one session store. Extending the guarantee cross-instance
  would require the store-level mechanism rejected below; this ADR only restores the single-JVM
  guarantee the code already claimed to provide.
- **Caffeine over a plain `ConcurrentHashMap`.** A plain map would leak an entry per distinct
  session id forever. Caffeine's `expireAfterWrite` bounds that without a separate cleanup task, and
  it's already on the classpath for this module.

## Consequences

**Positive**

- Closes the dedup bug for every `SessionRepository` CSL can be wired to today (persistent
  `WebSessionRepository` and the `MapSessionRepository` fallback), not just one of them.
- No change to any `*Port` contract — no host adapter (OC, Hub, or future adopters) has anything to
  update.
- The fix is contained to one class and does not add a new bean, configuration property, or public
  API surface.

**Negative / accepted trade-offs**

- The guarantee remains JVM-local. In a multi-instance deployment, concurrent requests for the same
  session landing on different application instances can still each independently refresh. This is
  an accepted, pre-existing limitation (see previous point), not a regression, and is out of scope
  for this ADR.
- A second, JVM-local bookkeeping structure now exists alongside the session-attribute-persisted
  `AUTH_LAST_REFRESH`. The two can theoretically diverge (e.g. after a JVM restart the cache is
  empty while the session attribute still holds an old timestamp) — harmless, because an empty cache
  entry is treated the same as "never claimed", which correctly allows exactly one refresh to
  proceed.
- The `maximumSize` bound is not correctness-neutral the way the TTL is: capacity-driven eviction
  of a still-active session's entry reopens the exact race this ADR closes, for that one session,
  until it claims again. Accepted because 10,000 concurrently-active sessions per JVM is already a
  large working set relative to typical CSL host deployments, the reopened race is no worse than
  the pre-fix behavior (not a regression), and sizing the cache to be practically unreachable would
  reintroduce unbounded growth as a real host-configurable size trades off against — the same
  problem the bound exists to prevent.

## Alternatives Considered

- **Store-level compare-and-set on `SessionStorePort`** (the direction suggested in
  camunda-security-library#510). Rejected: it would require adding a new method to an outbound port
  every host adapter implements (a breaking change requiring every adopter to update), and it would
  only cover the persistent-session path through `WebSessionRepository` — the default,
  non-persistent surface falls back to Spring Session's own `MapSessionRepository`
  (ADR-0031), which never goes through `SessionStorePort` at all. It would fix one path and leave
  the other exposed.
- **Lock keyed by session id, still gated on `session.getAttribute(LAST_REFRESH_ATTR)`.** Rejected
  on its own: as explained in Context, serializing the code path without changing what's read as the
  decision input does not close the stale-snapshot gap — a second thread can still observe an
  expired attribute value copied before the first thread's `save()` committed.

## Addendum: claim validity is judged by observed staleness, not elapsed time (camunda-security-library#517)

The original `compute` remap reused `isRefreshRequired(lastClaimed, now)` — the same elapsed-time
check used for session-attribute staleness — to decide whether an existing claim was still valid.
That conflates two different things: `authentication-refresh-interval` is a business refresh
cadence, not a bound on how long concurrent requests take to resolve one staleness episode.

Because the claim is advanced *before* the refresh side effects run, a second caller whose own
`compute` call happened to run after the interval had elapsed — trivial under CI scheduling jitter
— would see the winner's claim as "expired" and trigger a redundant second refresh for the same
staleness episode. This matches what CI showed: one early timestamp plus several requests
converging on one later, shared timestamp.

**Fix:** judge claim validity against `observedLastRefresh` — the staleness the calling thread
itself observed — instead of elapsed time. A claim is only re-claimable once it predates that
observation, regardless of how long the current claimant takes to finish. This holds for any
refresh interval, including ones short enough for scheduling jitter to exceed.

Verified by `HttpSessionBasedAuthenticationHolderTest#shouldNotReclaimWhenWinningClaimHasNotYetWrittenBackToSession`:
it reliably fails under the old elapsed-time predicate and passes with the fix.
