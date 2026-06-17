---
status: Accepted
---

# ADR-0028: Extend CSL authorization model to serve both search-layer and zeebe engine

**Deciders**: Patrick Wunderlich, Ben Sheppard, Meggle

## Status

Accepted

## Context

CSL is the common identity library for the Camunda platform. It currently carries an authorization
model used by the search (OC/Hub reader) layer via `AuthorizationChecker` and `ResourcePermissionPort`.
The zeebe engine carries a parallel implementation (`AuthorizationCheckBehavior`) that serves the
same logical purpose — checking whether a principal may perform an operation — but is backed by
different storage (RocksDB state instead of secondary index) and returns richer failure detail.

As CSL expands to cover engine-side identity concerns, the engine should use the same CSL
authorization framework rather than maintaining a separate parallel implementation. This ADR
identifies what is currently missing from CSL's authz model to also serve the zeebe engine, and
records the decisions on how to fill those gaps in a way that benefits both layers.

**What CSL's authz model currently provides:**

- `ResourcePermissionPort` (`core/port/in/`) — inbound port; `hasPermission()` returns `boolean`
- `AuthorizationChecker` (`core/authz/`) — scope evaluation kernel backed by two outbound ports
- `AuthorizationScopeRepositoryPort` (`core/port/out/`) — storage-agnostic scope query port
- `MembershipPort` (`core/port/out/`) — lazy membership resolution port
- `RequiredAuthorization<T>` (`core/auth/`) — specifies what check is required (`resourceType`,
  `permissionType`, `resourceIds`, `condition`, `transitive`)
- `CamundaAuthentication` (`api/model/`) — principal context with lazy membership chains
  ([ADR-0011](0011-lazy-load-authentication-memberships.md): lazy membership resolution via `*Supplier` builder methods)

**What is missing to also serve the zeebe engine:**

1. **Richer failure type**: the engine needs to know *why* authorization was denied
   (tenant assignment failure vs. resource permission failure) for cross-partition rejection
   broadcast. The current `boolean` return does not carry this.
2. **Tenant access check**: whether the principal is assigned to the tenant owning a resource.
   This is distinct from resource permissions and is not currently in the CSL authz model.
3. **Property-based authorization**: whether the principal can access a resource based on
   resource properties (e.g., user-task `assignee`, `candidateUsers`, `candidateGroups`). No
   equivalent in the current scope-based `AuthorizationChecker`.
4. **Spring-free claims converter**: the engine has raw `Map<String,Object>` claims and no
   Spring context. The existing `LazyTokenClaimsConverter` in `spring-boot-starter` cannot be
   used directly.
5. **Skip-checks query**: whether authorization checks are globally disabled (both authz and
   multi-tenancy off) — useful to avoid constructing auth objects on the command hot path.

The question this ADR answers: what additions or extensions to the existing CSL authz model make
it complete enough for the zeebe engine, while keeping all new types general-purpose?

## Decision

### 1. No new Maven module

All additions land in `core`, which is already Spring-free (`DomainArchTest` enforces this). A
dedicated module may be split out from `core` later if needed (see “Split `core` into `authz-core` + `authn-core`” in Alternatives Considered).

### 2. Introduce `AuthorizationCheckPort` (`core/port/in/`) as the unified inbound port

A new inbound port covers all check variants needed by both layers: scope-based, tenant, property-based, and skip-checks. Scope/tenant/property checks return `Either<AuthorizationRejection, Void>` rather than
`boolean`, carrying the reason for denial when authorization fails. The port also exposes a separate
skip-checks query returning `boolean` for hot-path short-circuiting. Both the search layer and the
zeebe engine use this port.

Port signatures use the existing CSL types (`CamundaAuthentication`, `RequiredAuthorization<T>`)
rather than introducing a new bundled request type. If `RequiredAuthorization<T>` needs extension
to carry tenant context or resource properties, that extension is general-purpose. The exact API
shape is an implementation decision for Inc 1 of the migration epic.

### 3. Add general-purpose failure types to `core`

- `Either<L, R>` — simple two-variant sealed type; replaces `io.camunda.zeebe.util.Either` used
  in the current zeebe implementation
- `AuthorizationRejection` — general-purpose failure type with two subtypes:
  - `AuthorizationRejection.Tenant` — principal not assigned to the required tenant
  - `AuthorizationRejection.Permission` — principal lacks the required resource permission

  These subtypes are not engine-specific; they describe the two logical reasons any CSL
  authorization check can fail, regardless of storage layer.
- `RejectionAggregator` — utility for composing multiple `AuthorizationRejection` instances into
  a single rejection response (e.g., after OR-semantics checks across multiple requests)

### 4. Add `PropertyAuthorizationEvaluator<T>` interface to `core`

A general-purpose evaluator interface for property-based authorization: "does the principal, based
on their claims, have access to a resource described by property values of type `T`?" Concrete
evaluators register against this interface via `PropertyAuthorizationEvaluatorRegistry`. The
interface is not zeebe-specific; future resource types may define their own evaluators.

Concrete evaluators that inspect engine-internal resource structures (e.g.,
`UserTaskPropertyAuthorizationEvaluator`) stay in `zeebe/engine` — they evaluate
engine-specific resource properties and are not CSL concerns.

### 5. Add `ClaimsAuthenticationConverter` to `core`

A Spring-free converter: `Map<String,Object> claims` + `MembershipPort` →
`CamundaAuthentication` with lazily-resolved membership chains. Mirrors the
`LazyTokenClaimsConverter` pattern (same `Supplier`-based wiring via
`CamundaAuthentication.lazyList`) but without Spring dependencies, making it usable in the
zeebe engine and any non-Spring CSL consumer.

**Dual-path for group resolution**: the engine's `MembershipPort.groupIds()` adapter must
implement `ClaimsExtractor`'s existing dual-path: check `Authorization.USER_GROUPS_CLAIMS` in
the claims map first (pre-resolved groups); fall back to `MembershipState` if absent.

### 6. Add `AuthorizationService` to `core` as the default `AuthorizationCheckPort` implementation

`AuthorizationService` implements `AuthorizationCheckPort` by orchestrating:

**(a) Scope-based checks**: delegates to `AuthorizationChecker`; the `boolean` result maps to
`AuthorizationRejection.Tenant` or `AuthorizationRejection.Permission` depending on which
check type failed.

**(b) Property-based checks**: delegates to the registered `PropertyAuthorizationEvaluator<T>`
for the resource type. There is no equivalent path in `AuthorizationChecker`; the two
evaluation paths within `AuthorizationService` must be documented explicitly in the class.

**(c) Skip-checks**: exposes a `boolean` query that returns `true` when both authz and multi-tenancy are disabled globally.

In `spring-boot-starter`, `AuthorizationService` is wired as a Spring bean by
`AuthorizationConfiguration` (following the same `@ConditionalOnMissingBean` pattern as
`AuthorizationCheckerConfiguration`). The zeebe engine receives the `AuthorizationService`
instance from the Spring context — the dist module's `BrokerModuleConfiguration` passes the
bean reference into the engine during bootstrap, so the engine itself does not need to
construct it or manage its dependencies.

### 7. Reuse `MembershipPort` + `AuthorizationScopeRepositoryPort` as unified outbound ports

No new outbound ports are introduced. The zeebe engine provides RocksDB-backed implementations
of both existing ports.

**`MembershipPort` fit — verified against the zeebe source:**
`AuthorizationScopeResolver.getScopesForEntity()` resolves scopes via direct + via roles
(`membershipState.getMemberships(ownerType, ownerId, ROLE)`) + via groups
(`ClaimsExtractor.getGroups()`). These map to `MembershipPort.roleIds()` + `groupIds()` chains.
The full resolved owner-ID set `{USER/CLIENT, GROUP, ROLE, MAPPING_RULE}` is then passed to
`AuthorizationScopeRepositoryPort`, which matches the port's existing `Map<EntityType, Set<String>>`
contract ([ADR-0022](0022-resource-access-control-framework-ownership.md)).

`MappingRuleMatcher` (`core/auth/`) already handles mapping-rule matching in both zeebe and CSL
today. No migration needed.

The search layer retains its existing outbound port implementations unchanged.

**Caching**: the engine's RocksDB adapters cache their results internally (Guava `LoadingCache`).
Caching is an adapter-layer concern; `core` stays dep-free. This moves caching from per-request
(current `AuthorizationCheckBehavior` cache keyed on the full request) to per-adapter
(membership + scope caches keyed on owner IDs and resource type). Inc 4 of the migration epic
must verify that performance is equivalent to the current per-request cache via the existing
authorization benchmark (baseline captured in Inc 0b).

### 8. `ResourcePermissionPort` transition

`ResourcePermissionPort` (existing `hasPermission()` → `boolean`) is kept for backwards
compatibility. Migrating search-layer callers to `AuthorizationCheckPort` is deferred to a later
increment (Inc 5) once the engine path stabilizes. `ResourcePermissionService` may be updated to
delegate to `AuthorizationService` internally.

### Why these particular boundaries

- `AuthorizationScopeRepositoryPort` receives pre-resolved `Map<EntityType, Set<String>> ownerIds`
  ([ADR-0022](0022-resource-access-control-framework-ownership.md)) — storage-agnostic by construction. The engine's RocksDB adapter satisfies the same
  contract as the search-layer adapter without changes to the port.
- `LazyList` in `CamundaAuthentication` ([ADR-0011](0011-lazy-load-authentication-memberships.md)) makes lazy membership resolution Spring-free.
  `ClaimsAuthenticationConverter` reuses the same `Supplier`-based pattern as
  `LazyTokenClaimsConverter` without any `spring-boot-starter` dependency.
- `MappingRuleMatcher` already bridges both zeebe and CSL — no migration work, just continued use.
- `core` is already Spring-free; `DomainArchTest` enforces this. Verify existing pattern matchers
  cover the new packages; extend if needed.
- Caching at the adapter layer (not in `AuthorizationService`) keeps `core` dependency-free and
  respects the hexagonal boundary: the infrastructure concern stays in the adapter.

## Consequences

**Positive**

- Single scope evaluation kernel (`AuthorizationChecker`) shared by both layers; semantic drift
  between search-layer and engine authz is structurally prevented.
- No new Maven module or outbound port contracts — the engine integrates against what already
  exists in `core` plus the new `AuthorizationCheckPort`.
- `AuthorizationRejection` and `Either` are general-purpose; the search layer benefits from them
  once it migrates to `AuthorizationCheckPort` (a future increment, not this epic).
- `zeebe/engine` implements two focused RocksDB adapters for existing outbound ports; no new port
  contracts need stabilizing before the engine integration begins.
- `ClaimsAuthenticationConverter` makes raw-claims-to-auth conversion available to any non-Spring
  consumer of CSL, not just the zeebe engine.

**Negative / accepted trade-offs**

- `core` grows with new types (`Either`, `AuthorizationRejection`, `RejectionAggregator`,
  `PropertyAuthorizationEvaluator`, `ClaimsAuthenticationConverter`, `AuthorizationService`).
  These are all general-purpose. If `core` feels large over time, extract a dedicated module
  (see Alternative B).
- `PropertyAuthorizationEvaluator` is a separate evaluation path in `AuthorizationService`
  alongside the scope-based path. Callers must not bypass it; this must be documented explicitly
  in the class.
- `ClaimsAuthenticationConverter` mirrors `LazyTokenClaimsConverter`. Both must stay aligned
  when `MembershipPort`'s shape changes. Extract a shared base utility later if the duplication
  becomes a maintenance burden.
- No caching in `AuthorizationService` in `core`. The zeebe engine's per-command performance
  relies on caching inside the RocksDB adapter implementations — Inc 4 must treat this as a
  required concern, not a nice-to-have optimisation.
- `MembershipPort.groupIds()` adapter must implement a dual path: `USER_GROUPS_CLAIMS` claim
  first, then `MembershipState`. This must be documented in Inc 4 acceptance criteria.

## Alternatives Considered

- **Separate engine-authz module with new port contracts, no reuse of existing CSL ports.**
  Rejected — duplicates scope evaluation already in `AuthorizationChecker`; a new `IdentityStatePort`
  is superseded by the existing `MembershipPort` + `AuthorizationScopeRepositoryPort`.
- **Split `core` into `authz-core` + `authn-core`; engine depends on `authz-core` only.**
  Deferred — the engine needs both concepts (claims extraction is authn, scope checks are authz).
  A split adds Maven overhead with no dependency hygiene gain at current scale. Revisit if `core`
  grows significantly.
- **Keep zeebe engine's `AuthorizationCheckBehavior` as a separate parallel evaluator, no
  migration into CSL.** Rejected — the two evaluators diverge over time; bugs fixed in one are
  not fixed in the other; maintenance burden grows as the platform expands.
