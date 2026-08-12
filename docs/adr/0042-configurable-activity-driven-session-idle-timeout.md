---
status: Accepted
---

# ADR-0042: Configurable session idle timeout driven by client activity, not request traffic

**Deciders**: Timothy Cline (timcline)

## Status

Accepted

## Context

No CSL-embedded webapp session has a configurable idle timeout today. `WebSessionRepository.createSession()`
never calls `setMaxInactiveInterval(...)`, so every session — persistent or in-memory — inherits Spring
Session's `MapSession` default of 30 minutes, undocumented and unchangeable by any host.

Separately, whatever interval a session has is currently measured against **request traffic**, not genuine
user presence. Spring Session's `SessionRepositoryFilter` unconditionally touches `lastAccessedTime` at the
end of every request that accessed the session (`commitSession()` calls `session.setLastAccessedTime(Instant.now())`),
and `WebSession` only ever suppresses that for requests explicitly tagged `x-is-polling`. In practice this
means an idle browser tab that happens to trigger any ordinary backend call — a background poll not tagged
as such, a stray fetch — keeps resetting the clock even though no one is actually at the keyboard. The
mechanism doesn't measure what an idle timeout is supposed to measure.

Deployments with stricter security requirements need both: a host-configurable idle-timeout duration, and
for that duration to be measured against real browser activity (mouse movement, clicks) rather than
backend traffic. The second part is a behavior change with real consequences if rolled out carelessly — a
host that stops trusting request traffic as an activity signal needs its frontend to actually supply a
replacement signal before that change takes effect, or users get logged out regardless of how actively
they're using the application.

The question this ADR answers: what configuration surface and mechanism let a host measure session idle
timeout against genuine client-side activity instead of request traffic, without silently changing existing
behavior for any host that hasn't opted in?

## Decision

**Two new properties**, both under the existing `SessionConfiguration` (`api/model/config/`), sibling to
`persistent.enabled`:

- `camunda.security.session.max-inactive-interval` (`java.time.Duration`, default `30m`) — the idle-timeout
  duration itself. Bound as a native `Duration` rather than following `authentication-refresh-interval`'s
  precedent (a `String` parsed manually via `Duration.parse`, which only accepts strict ISO-8601 like
  `PT30M`): Spring Boot's relaxed `Duration` binding accepts `30m`, `1800s`, or `PT30M` alike, a deliberate
  ergonomic improvement scoped to this new property.
- `camunda.security.session.heartbeat.enabled` (`boolean`, default `false`, under a new nested
  `HeartbeatConfiguration`) — gates whether the interval above is measured against request traffic (off,
  today's unchanged behavior) or against a dedicated heartbeat call (on).

**A new per-scope endpoint**, `POST {basePath}/session/heartbeat`, installed on every webapp chain — the
primary surface and every physical-tenant scope, both OIDC and Basic-auth chains — the same way `/login`,
`/logout`, and `/sso-callback` already derive from `basePath` ([ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md)
§1). Reusing that derivation gets correct per-scope cookie/session routing for free and needs no new
scoping design.

**`WebSession.setLastAccessedTime()`'s existing touch guard becomes config-aware**:

- `heartbeat.enabled=false` (default): unchanged — touch unless the request is tagged `x-is-polling`.
- `heartbeat.enabled=true`: touch *only* when the request is the recognized heartbeat call; every other
  request, polling or not, is a no-op.

`WebSessionRepository` already inspects the current `HttpServletRequest` to compute `isPollingRequest`
today; the same inspection point extends to also recognize the heartbeat path and branch on the flag. The
`x-is-polling` exclusion is **not retired** — it remains the exact flag-off behavior for any host that
doesn't opt in, and only becomes moot once a host turns the flag on for its own deployment (at which point
nothing but the heartbeat touches the session, so there's nothing left for a polling request to be excluded
from).

**No new logout or expiry-detection mechanism.** `shouldBeDeleted()`, the deletion-on-access path, and the
background expiry sweep are unchanged. Once the configured interval elapses, the next access already marks
the session for deletion, and the following request has no valid session — the existing security-chain
entry point takes over exactly as it does for any unauthenticated request.

**A shared, versioned frontend package** (e.g. a `useSessionHeartbeat()` hook) ships the throttled
activity-listener and heartbeat-call logic, following the existing npm-package integration model
([ADR-0005](0005-frontend-integration-for-hub-and-oc.md)), for consuming teams to import rather than each
independently reimplementing the same listener/throttle logic.

This is an **idle timeout, not an absolute session lifetime**. `WebSession`/`PersistentSession`'s existing
`creationTime` field is untouched by this decision; a hard cap on total session lifetime regardless of
activity is a separate, explicitly out-of-scope control (see Consequences).

### Why these particular boundaries

- **Config-gated, not an unconditional flip.** A host gets the configurable interval immediately with zero
  behavior change, and only takes on the activity-source change once its frontend has adopted the
  heartbeat package. This turns a hard cross-team dependency (backend change requires frontend cooperation
  to behave correctly) into an explicit, host-sequenced opt-in instead of a footgun baked into one release.
- **Repurposes the existing polling-exclusion lever rather than adding a parallel one.** The inspection
  point that already recognizes `x-is-polling` is the natural place to also recognize the heartbeat path —
  a change to one existing, narrow method, not new plumbing.
- **Endpoint derived from `basePath`, not a new scoping mechanism.** Reuses ADR-0027's pattern so per-scope
  cookie/session routing, and support for both OIDC and Basic auth, come for free.
- **Shared frontend package over ad hoc per-app implementations.** Centralizes throttle/listener logic in
  one versioned artifact instead of every consuming team (Operate, Tasklist, Optimize, and future adopters)
  solving — and likely drifting on — the same problem independently. Mirrors ADR-0005's chosen npm-package
  model rather than inventing a new frontend-distribution mechanism.

### Default implementations and override boundaries

| Contract / property | Provided by | Default / off behavior |
|---|---|---|
| `max-inactive-interval` | Host config | `30m` — same effective duration as today's hardcoded default |
| `heartbeat.enabled` | Host config | `false` — today's touch-on-every-request behavior, unchanged |
| `POST {basePath}/session/heartbeat` | CSL (installed on every webapp chain) | Present regardless of the flag; only load-bearing once `heartbeat.enabled=true` |
| Shared frontend package | CSL / frontend org, published npm package | Optional import; not adopting it just means `heartbeat.enabled` should stay off |

## Consequences

**Positive**

- The idle timeout becomes a documented, host-configurable value instead of a silent, hardcoded default.
- Once a host opts in, the timeout measures what it's meant to measure — genuine browser presence — instead
  of being reset by incidental backend traffic.
- Fully backward compatible: both properties default to today's exact behavior; no existing deployment sees
  a behavior change without explicit, deliberate opt-in.
- Centralizing the frontend logic in one shared package avoids drift across Operate, Tasklist, Optimize,
  and any future adopter.
- No `SessionStorePort` or other port-contract changes; reuses `shouldBeDeleted()`, the deletion sweep, and
  the existing per-scope chain-building patterns unchanged.

**Negative / accepted trade-offs**

- Two related but independent config properties instead of one; a host can still misconfigure by enabling
  `heartbeat.enabled` before its frontend has adopted the package, causing user-visible early logouts. The
  flag defaulting off mitigates this but doesn't eliminate the possibility of a host getting the sequencing
  wrong.
- The shared frontend package becomes a new versioned artifact this initiative has to own, publish, and
  support; consumers only receive a behavior fix (e.g. a throttle-interval tuning change) when they bump
  the dependency, not automatically.
- Console and Web Modeler get none of this until/unless they adopt CSL — tracked separately
  (`docs/migration_path.md`, currently WIP) and out of scope for this decision.
- An absolute session-lifetime cap, independent of activity, is explicitly not addressed here. If wanted
  later it is a cheap follow-on — `WebSession`/`PersistentSession` already carry `creationTime` — but it is
  a separate decision, not folded into this one.

## Alternatives Considered

- **Reuse Spring Boot's `server.servlet.session.timeout`** instead of a new CSL property. Rejected — CSL
  deliberately does not rely on Spring Boot's own session machinery
  ([ADR-0031](0031-explicit-default-session-filter-replaces-global-filter.md) removed
  `@EnableSpringHttpSession`); repurposing a Boot-owned property whose usual meaning doesn't match what CSL
  does underneath would be a less explicit activation path than this library's opt-in-by-name convention
  ([ADR-0008](0008-no-spring-boot-auto-configuration.md)).
- **Inverse header-tagging on ordinary business calls** to mark selected requests as "this counts as
  activity," instead of one dedicated endpoint. Rejected — spreads the contract across every call site in
  every frontend that wants to opt in; easy to forget on a new API call, hard to audit.
- **Purely client-side enforcement** (the browser runs its own idle timer off the same listeners and calls
  `/logout` itself, with no periodic heartbeat to the server). Rejected — a security-relevant timeout needs
  a server-side authoritative record. A crashed tab, a dropped connection, or a modified client that simply
  never calls `/logout` would leave the session valid server-side indefinitely relative to actual
  inactivity.
- **Leave each consuming frontend to build its own listener/throttle logic** against the published endpoint
  contract, with no shared package. Rejected — invites drift in throttle interval and event handling across
  apps, and duplicates the same non-trivial logic in every consumer instead of once.
- **Retire the `x-is-polling` exclusion outright** as part of this change. Rejected — it must remain the
  exact flag-off behavior for any host that never opts in; it only becomes redundant once a host turns
  `heartbeat.enabled` on for its own deployment, not unconditionally.
