---
status: Superseded by ADR-0028
---

# ADR-0007: Two-port authorization surface (`ResourcePermissionPort` and `AuthorizationRepositoryPort`)

## Status

Superseded by [ADR-0028](0028-unified-authz-framework-in-core.md).

Both ports defined here — `ResourcePermissionPort` (inbound) and
`AuthorizationRepositoryPort` (outbound) — were removed in #399 once the webapp
authorization filter, their last consumer, was rerouted through the unified
`AuthorizationCheckPort`. See ADR-0028 decision 8. The historical context below is
retained for the record.

## Context

The CSL needs to enforce authorization checks from inside the library (filters, services) without owning the host's authorization data store, while also being able to gradually take over the matching/decision logic that currently lives in OC's `ResourceAccessProvider`. Two adjacent concerns are visible:

1. **Decision** — given an authenticated principal and an authorization question ("does this principal have permission `P` on resource type `R` with id `i`?"), produce a `ResourceAccess` verdict (`Allowed` / `Wildcard` / `Denied`). The decision applies matching rules across the principal's groups, roles, and mapping rules.
2. **Data** — fetch the raw authorization records that apply to a principal, so a decision can be made over them.

Today (May 2026), OC implements both concerns inside its own `ResourceAccessProvider`. We want to lift the surface into the CSL while leaving room to lift the decision logic too, without forcing the data layer into the library prematurely.

A naïve single-port surface — "host implements one method that takes auth + question and returns `ResourceAccess`" — was tried in early iterations of #69 and produced two failure modes: it duplicated identical signatures across an inbound and an outbound interface (the library default just delegated, encapsulating nothing); and it left no clean seam for the library to take over decision logic later without changing the host-facing contract.

## Decision

The CSL exposes two ports with distinct responsibilities:

### `ResourcePermissionPort` — inbound, decision layer

- **Location:** `core/port/in/ResourcePermissionPort.java`
- **Signature:** `boolean hasPermission(CamundaAuthentication authentication, ResourceType resourceType, String resourceId, PermissionType permissionType)`
- **Inputs:** the migrated `ResourceType` and `PermissionType` enums in `api/model/` (lifted from `io.camunda.zeebe.protocol.record.value.AuthorizationResourceType` / `PermissionType` — the originals were unreachable due to the ArchUnit ban on zeebe-protocol imports), plus the specific `resourceId` being checked.
- **Role:** library callers (filters, services in the starter) invoke this to ask whether a principal holds a permission on a specific resource. It is the contract the rest of the library speaks against.
- **Implementation:** the library ships `ResourcePermissionService` (in `spring-boot-starter`) as the default. It delegates to the host-supplied `AuthorizationRepositoryPort` for data and applies the permission match centrally. Hosts that need different decision semantics (caching, alternative matching) register their own `ResourcePermissionPort` bean and the library default backs off via `@ConditionalOnMissingBean`.

Earlier iterations of this PR experimented with a richer return shape (`ResourceAccess` sealed type) and a query record (`Authorization<T>` with builder). Both were rejected: the actual question filters ask is a yes/no on a specific resource, and a fluent question record adds ceremony without value. A batch-listing variant (e.g. "which components can Alice see?") returning `Allowed(Set<String>) | Wildcard | Denied` can be added as a separate method later when a caller demands it — adding it speculatively now would force every caller to handle the trichotomy for no benefit. Wildcard semantics on a single grant ("ACCESS on all components") is also deferred — it can be added as a one-line change to the matching predicate when needed without affecting the host SPI.

### `AuthorizationRepositoryPort` — outbound, data layer

- **Location:** `core/port/out/AuthorizationRepositoryPort.java`
- **Signature:** `Set<Authorization> findAuthorizations(CamundaAuthentication authentication, ResourceType resourceType)`
- **Returns:** a set of `Authorization` records (`api/model/Authorization`), each carrying `(resourceType, resourceId, Set<PermissionType>)` — what the principal is granted on a resource of the requested type.
- **Role:** isolates the host's data store from the library's decision logic. Hosts implement this with their concrete adapter (named `*Adapter` per the team convention — e.g. `SearchAuthorizationRepositoryAdapter`). Implementations should resolve the principal's identity transitively (direct user/client grants plus grants reachable via groups, roles, and mapping rules).
- **Why split the data layer out:** lets the library own and evolve the matching logic centrally (caching, instrumentation, consistent semantics across hosts) while hosts continue to own only "where the records come from."

### Naming

Per the team's hex convention:

| Role | Interface | Implementation |
|---|---|---|
| Inbound | `*Port` in `core/port/in/` | `*Service` (typically in `spring-boot-starter/`) |
| Outbound | `*Port` in `core/port/out/` | `*Adapter` (host code) |

So: `ResourcePermissionPort` (inbound) ships with a default `ResourcePermissionService` in `spring-boot-starter`, and `AuthorizationRepositoryPort` (outbound) is implemented by hosts as `*RepositoryAdapter` (e.g. `SearchAuthorizationRepositoryAdapter`).

The earlier name `ResourceAccessProvider` was rejected: the library already exposes a permission named `ACCESS`, so a `*ResourceAccess*` interface name reads ambiguously next to it. `ResourcePermissionPort` describes the question being answered ("can this principal exercise this permission against this resource?") without colliding with the permission vocabulary.

### Module placement and dependency direction

Public types (`ResourceType`, `PermissionType` enums; `Authorization` record) live in `api/model/`, alongside the existing `CamundaAuthentication` — these are the host-facing data shapes. Ports live in `core/port/in/` and `core/port/out/` per the architecture doc.

For port signatures to speak the public records, the module dependency direction is **`core` → `api`**, not the reverse. `api` carries the public surface; `core` holds the domain ports that consume that surface. The architecture doc and `DomainArchTest` are updated accordingly (the previous `CORE_MUST_NOT_DEPEND_ON_API` rule is removed; `api` no longer carries an annotation-only `core` dep).

## Consequences

**Positive**

- Decision and data concerns separate cleanly. Hosts pick the implementation depth that fits their stage of migration: full ownership of `ResourcePermissionPort` today, or just `AuthorizationRepositoryPort` once the library default service ships.
- The library has a real seam to encapsulate decision logic centrally without breaking host contracts.
- Naming aligns with the team's hex convention (`*Port` interfaces, `*Service`/`*Adapter` implementations) and with the architecture doc's placement rules.
- `DomainArchTest` keeps the boundaries that still matter (no `core` → `starter`, no `core` → Spring/Servlet/Persistence/Jackson runtime/zeebe-protocol). The `core` → `api` edge is now a deliberate, narrow channel for public types.

**Negative / accepted trade-offs**

- The `core` → `api` dependency reverses the previous "api layered on core" framing. The change is small in code (`api` had zero actual `core` imports — only an annotation-only dep) but conceptually meaningful: `api` is the public surface, `core` builds on it.
- The default `ResourcePermissionService` ships unwired in #69 — the class is present in `spring-boot-starter`, but the auto-configuration that registers it (with `@ConditionalOnMissingBean` back-off) lands alongside the filter wiring in #57. Hosts that pull the dependency before #57 lands can still construct `ResourcePermissionService` manually if they need to.

**Implementation notes**

- #69 ships the full surface: both ports, the migrated `ResourceType` / `PermissionType` enums, the `Authorization` data record, the dep-direction change, and the library's default `ResourcePermissionService`.
- Hosts (Hub, OC) implement `AuthorizationRepositoryPort` to plug their data stores into the default service. Hosts that need different decision semantics override `ResourcePermissionPort` directly and the library default backs off via `@ConditionalOnMissingBean`.

## Alternatives Considered

- **Single port, host owns everything (early #69 attempt).** Rejected — duplicated identical signatures across an inbound/outbound pair, left no seam for the library to take over decision logic later.
- **Records and ports both in `api/`, hex-naming applied inside `api/`.** Rejected — bends the architecture doc's placement rule for ports (`core/port/in/`, `core/port/out/`).
- **Records in `core/`, ports in `core/`, hosts importing `core`.** Rejected — hosts (notably OC) should depend only on `api/` for the public surface; pulling `core` into host classpaths leaks domain internals.
