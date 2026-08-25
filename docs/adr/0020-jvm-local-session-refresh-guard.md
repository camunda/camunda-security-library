---
status: Accepted
---

# ADR-0020: JVM-local, session-ID-keyed guard for authentication refresh dedup

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
([ADR-0012](0012-session-store-port-and-web-session-ownership.md) removed the last path
that used the servlet container's native, per-ID-stable `HttpSession`). `request.getSession(false)`
now always goes through `SessionRepository.findById(id)`, and every `SessionRepository`
implementation in play returns a fresh object per call for the same underlying session id:

- CSL's own `WebSessionRepository` (persistent sessions, ADR-0012) calls
  `sessionStorePort::get`, which round-trips the host's storage and constructs a new `WebSession`
  each time ([`WebSessionRepository.java:67-74`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/session/WebSessionRepository.java#L67-L74)).
- Spring Session's own `MapSessionRepository` — the fallback used for the default surface when
  persistence is off (ADR-0012) — also returns `new MapSession(saved)`, a copy, on every
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
  a claim is re-claimable once it is no newer than the `AUTH_LAST_REFRESH` value this request
  already read from its own session snapshot — captured before the `compute` remap runs, and not
  re-read inside it. Claim validity is judged against that captured value, deliberately **not**
  against elapsed wall-clock time compared to `authentication-refresh-interval`: reusing the
  elapsed-time staleness check here let a second caller's `compute` — running after the interval
  had passed, easy to hit under scheduling jitter — see the winner's claim as "expired" and trigger
  a redundant second refresh for the same staleness episode. Judging against the captured value
  instead holds for any refresh interval, including ones short enough for jitter to exceed. Only
  the caller whose `compute` sees a claim no newer than that captured value performs the refresh
  (`removeCamundaAuthenticationInSession` + `session.setAttribute(LAST_REFRESH_ATTR, now)`) and
  advances the claim; every other concurrent caller — regardless of which `HttpSession` object it
  holds — sees an already-current claim and skips. The winning caller is identified by **reference
  equality** on the `now` `Instant` it passed into `compute`, not `Instant.equals(...)`: two
  concurrent callers can capture value-identical instants when clock resolution is coarser than the
  race window, so value equality alone cannot tell which caller's write actually landed.
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
- `refreshClaims` carries **no `maximumSize` cap** — it is bounded by `expireAfterWrite` only. An
  earlier design paired the TTL with `maximumSize(10_000)` as a memory-safety backstop, but a
  capacity-driven eviction is *not* correctness-neutral the way TTL eviction is: Caffeine can evict
  an entry for capacity reasons before its TTL elapses, including — in principle — an entry for a
  session that is still genuinely active, which reopens the original race for that one session (a
  concurrent `compute` sees a miss and treats it as "never claimed"). The cap was dropped for
  exactly this reason — see Consequences for the accepted trade-off this leaves in its place.
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
- With no `maximumSize` cap, cache growth is bounded only by how many distinct sessions actually
  refresh within roughly the TTL window (Caffeine reaps expired entries lazily, on subsequent
  cache access, not the instant they go stale), not by any enforced maximum. Accepted because this
  growth is proportional to genuine concurrent load rather than an unconditional leak, and a hard
  cap's only benefit — a memory ceiling — came at the cost of silently reopening the exact race
  this ADR closes, under the highest-load conditions where that matters most.

## Alternatives Considered

- **Store-level compare-and-set on `SessionStorePort`** (the direction suggested in
  camunda-security-library#510). Rejected: it would require adding a new method to an outbound port
  every host adapter implements (a breaking change requiring every adopter to update), and it would
  only cover the persistent-session path through `WebSessionRepository` — the default,
  non-persistent surface falls back to Spring Session's own `MapSessionRepository`
  (ADR-0012), which never goes through `SessionStorePort` at all. It would fix one path and leave
  the other exposed.
- **Lock keyed by session id, still gated on `session.getAttribute(LAST_REFRESH_ATTR)`.** Rejected
  on its own: as explained in Context, serializing the code path without changing what's read as the
  decision input does not close the stale-snapshot gap — a second thread can still observe an
  expired attribute value copied before the first thread's `save()` committed.
