---
status: Accepted
---

# ADR-0029: Per-scope session store ownership for durable web sessions

**Deciders**: Ben Sheppard (Ben-Sheppard), Sebastian Bathke (megglos), Joaquin Felici (joaquinfelici)

## Status

Accepted

Revises [ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md) §6 (durable
per-scope session routing). ADR-0027's other sections (per-scope chains, prefix-aware resolver,
cookie/session isolation, the scoped API chain honouring the session, registrar) stand unchanged.

## Context

[ADR-0017](0017-session-store-port-and-web-session-ownership.md) gave CSL ownership of the web-session
lifecycle behind the host's `SessionStorePort`. [ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md)
added per-scope webapp/API chains for physical-tenant deployments: each scope
(`/physical-tenants/<id>`) gets its own `SessionRepositoryFilter` with a `Path`-scoped, distinctly
named cookie, so a browser holding several scopes' sessions never sends one scope's cookie to
another. For durable storage, ADR-0027 §6 kept `SessionStorePort` unchanged and made the host's
`SessionStoreAdapter` resolve the per-tenant `PersistentWebSessionClient` via
`withPhysicalTenant(PhysicalTenantContext.current())` — asserting that request-scoped
`get`/`upsert`/`delete` "run on the request thread, where `PhysicalTenantFilter` has already stamped
`PhysicalTenantContext`, so they route directly."

That assertion is false for the write path. Spring Session's `SessionRepositoryFilter` reads and
writes the store in `commitSession`, invoked from a `finally` block **after** `DispatcherServlet`
has torn down the request scope (`RequestContextHolder`). At that point `PhysicalTenantContext`
resolves to nothing and the adapter falls back to the **default** store
([ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md) §6 relied on the stamp
surviving; it does not). The symptoms:

- Non-PT / SaaS: a hard 500 at commit ([#55849](https://github.com/camunda/camunda/issues/55849)),
  patched by falling back to the default tenant when no scope is bound
  ([#55851](https://github.com/camunda/camunda/issues/55851)) — correct for the default surface only.
- Multi-PT: a non-default tenant's session is **written to the default store** at commit, then read
  back from the tenant's store on the next request — so the user can never stay logged in
  ([#55852](https://github.com/camunda/camunda/issues/55852)), the case this ADR resolves.

Two adjacent fixes bound the problem but do not solve routing. Propagating the tenant onto the
request thread across commit (a thread-local carried by an outer filter) works but keeps routing
*ambient* — sensitive to async/error dispatch and pooled-thread hygiene, and it does not cleanly
cover the outermost global session filter. Capturing the tenant into the lazy `CamundaAuthentication`
membership suppliers ([camunda#56261](https://github.com/camunda/camunda/pull/56261) /
[camunda-security-library#462](https://github.com/camunda/camunda-security-library/pull/462)) fixes
session *content* serialisation off-scope but not *where the session bytes are written*.

The question this ADR answers: how does a scope's durable session write land in that scope's store
at commit time, without depending on request- or thread-scoped `PhysicalTenantContext` — while
keeping CSL scope-agnostic and the `SessionStorePort` contract intact?

## Decision

Route durable per-scope session storage **structurally**: bind each scope's `SessionRepositoryFilter`
to its own store, so the store is decided by *which filter handles the request* (object identity),
not by ambient context read at commit.

### 1. `ScopedSessionStorePortProvider` — a per-scope store lookup (new SPI)

A new optional outbound contract in `core/port/out/`:

```java
public interface ScopedSessionStorePortProvider {
  /** The session store bound to the given scope's storage (one physical tenant). */
  SessionStorePort forBasePath(String basePath);
}
```

Keyed by **`basePath`** — the scope identity CSL already owns — so `core`/CSL never learns what a
scope *means* (ADR-0025/0027's scope-agnostic constraint holds). The host maps `basePath` → tenant
internally. `SessionStorePort` ([ADR-0017](0017-session-store-port-and-web-session-ownership.md)) is
**unchanged**: no tenant parameter added; each returned port is bound to exactly one store.

### 2. Per-scope `WebSessionRepository`, built by the registrar

When a `ScopedSessionStorePortProvider` bean is present, `ScopedSecurityChainRegistrar`'s
`getOrBuildSessionFilter(basePath)` builds a **per-scope** `WebSessionRepository` over
`provider.forBasePath(basePath)` (via a small factory in `WebSessionConfiguration` that owns the
`mapper` + request-proxy wiring) and injects it into that scope's `SessionRepositoryFilter`. Because
the filter holds its own repository, `commitSession` → `findById`/`save` route to the scope's store
by construction — no `PhysicalTenantContext` read at commit.

Resolution order, preserving backward compatibility:

1. provider present → per-scope `SessionStorePort`-backed `WebSessionRepository`;
2. else singleton `WebSessionRepository` present → today's shared behaviour;
3. else → per-scope in-memory `MapSessionRepository` (dev/test), as in ADR-0027 §3.

### 3. The global filter and the expiry sweep — single-store, no fan-out

Every `SessionStorePort` instance is bound to **exactly one** store; none performs a cross-store
`getAll`/`delete`. The two non-scoped concerns are wired accordingly:

- **Global filter.** CSL's `@EnableSpringHttpSession` registers a global `springSessionRepositoryFilter`
  (order `SessionRepositoryFilter.DEFAULT_ORDER`, outermost) that serves the **default surface** —
  non-PT deployments and the unprefixed cluster paths. Its `WebSessionRepository` is backed by a
  **default single-store** `SessionStorePort` (bound to the default physical tenant). No request/thread
  context is consulted; the default surface always maps to the default store.
- **Expiry sweep.** The context-free background sweep (`WebSessionDeletionTask`, ADR-0017)
  **iterates the per-scope repositories** (plus the default), running the expiry check against each
  store in turn. The all-tenants concern lives here, explicitly, rather than being hidden behind a
  fan-out `getAll`/`delete` on a shared adapter.

Consequently `PhysicalTenantContext` is no longer consulted anywhere in the session-storage path.

### 4. Host-side wiring

- A **single-tenant** `SessionStorePort` adapter, bound to one `PersistentWebSessionClient` resolved
  through the existing `PhysicalTenantScoped<PersistentWebSessionClient>.withPhysicalTenant(id)`
  provider (no bespoke client map — consistent with ADR-0027's rejection of an adapter-owned cache).
  It keeps the upsert retry policy. This is the **only** `SessionStorePort` shape.
- A `ScopedSessionStorePortProvider` implementation: `forBasePath("/physical-tenants/<id>")` → strip
  the prefix → single-tenant adapter for `<id>` (`default` included, as the ADR-0027 default alias).
- The global filter's `SessionStorePort` bean is the **default** single-store adapter
  (`withPhysicalTenant(default)`). There is no routing/fan-out adapter.
- **The host must return the *same* `SessionStorePort` instance** for the default surface and the
  `default` scope (e.g. the provider caches one adapter per tenant, and the global-filter bean reuses
  it for the default store). The expiry sweep deduplicates repositories by backing-store *identity*
  (`WebSessionConfiguration#distinctByStore`), so sharing the instance is what actually collapses the
  default store's otherwise-duplicate sweep; distinct instances backing the same store would each be
  swept.

### Why these particular boundaries

- **Structural over ambient.** Routing by filter identity is immune to request-scope teardown,
  async/error dispatch, and pooled-thread leakage — it removes the entire "context gone at commit"
  failure class for scoped storage, rather than papering over one trigger of it.
- **Keyed by `basePath`, not tenant.** Keeps `core`/CSL scope-agnostic; the tenant mapping stays
  host-side, matching ADR-0025/0027.
- **Reuse `PhysicalTenantScoped`, no adapter-owned map.** Same rationale ADR-0027 §6 used to reject a
  bespoke `Map<tenant, client>`; per-tenant resolution stays consistent with the rest of the codebase.
- **One adapter shape, one store each.** No `SessionStorePort` instance is silently cross-store; the
  only place that spans stores is the expiry sweep, which iterates them explicitly. This keeps the
  isolation boundary uniform and drops `PhysicalTenantContext` from the storage path entirely.

### Default implementations and override boundaries

| Contract | Provided by | Default / absent behaviour |
|---|---|---|
| `ScopedSessionStorePortProvider` | Host (optional) | Absent → registrar keeps shared singleton or `MapSessionRepository` (ADR-0027 §3) |
| `SessionStorePort` (per scope) | Host | One per scope, single-store; from `withPhysicalTenant(id)` |
| `SessionStorePort` (global filter) | Host | Default single-store adapter (`withPhysicalTenant(default)`) |
| Expiry sweep | CSL | Iterates the per-scope repositories (plus default); no fan-out adapter |

## Consequences

**Positive**

- A scope's durable session is written to and read from that scope's store at commit — [#55852](https://github.com/camunda/camunda/issues/55852) resolved.
- Robust by construction: no dependency on `PhysicalTenantContext` at commit, so no async/error-dispatch or thread-leak caveats, and no need to register the PT filter for extra dispatch types.
- One `SessionStorePort` shape (single-store, no context, no fan-out); `PhysicalTenantContext` drops out of the storage path entirely, and no adapter is silently cross-store. The `SessionStorePort` and `CamundaSecurityScopeProvider`/`ScopedSecurityDescriptor` contracts are unchanged; additive and backward-compatible (primary-only and non-PT hosts unaffected).
- Dissolves the read-by-id chicken-and-egg that made [#55741](https://github.com/camunda/camunda/issues/55741) (tenant id on `CamundaAuthentication`) insufficient for routing.
- Orthogonal to and composable with the membership-content capture fix ([camunda#56261](https://github.com/camunda/camunda/pull/56261) / [camunda-security-library#462](https://github.com/camunda/camunda-security-library/pull/462)): that fixes session *content* resolution, this fixes *storage routing*.

**Negative / accepted trade-offs**

- A new SPI (`ScopedSessionStorePortProvider`) adds host-facing surface.
- Each scope now owns a `WebSessionRepository` instance in addition to its filter/cookie serializer — negligible for small N (same caveat as ADR-0025/0027).
- The expiry sweep must enumerate the per-scope repositories to iterate every store, rather than relying on a single fan-out `getAll`/`delete`. This is a little extra wiring, but keeps every adapter single-store and the isolation boundary uniform.
- ADR-0027 §6's stated routing mechanism is revised; readers must consult this ADR for durable per-scope routing.

## Alternatives Considered

- **Propagate the tenant onto the request thread across commit** (an outer filter binds a `PhysicalTenantContext` thread-local, cleared in `finally`). Prototyped, then rejected — it works but keeps routing ambient: it depends on the propagating filter running on the commit thread (async/error dispatch), on strict thread-local hygiene to avoid cross-tenant leakage on pooled threads, and it does not cleanly cover the outermost global session filter. Structural routing removes those dependencies.
- **Store the physical tenant id on `CamundaAuthentication`** ([#55741](https://github.com/camunda/camunda/issues/55741)). Rejected for routing — it could carry the tenant for the *write*, but `findById` at commit is given only a session id and must pick the store *before* it can read the session, so the read is still unrouted. Complementary at best.
