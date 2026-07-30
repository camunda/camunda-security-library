---
status: Accepted
---

# ADR-0028: Extend CSL authorization model to serve both search-layer and zeebe engine

**Deciders**: Patrick Wunderlich, Ben Sheppard, Meggle

## Status

Accepted

## Context

CSL's authorization model today serves the search (OC/Hub reader) layer:
`ResourcePermissionPort` (inbound, `boolean hasPermission()`), the `AuthorizationChecker`
scope-evaluation kernel, the outbound `AuthorizationScopeRepositoryPort` and `MembershipPort`,
`RequiredAuthorization<T>`, and `CamundaAuthentication` with lazy membership resolution
([ADR-0011](0011-lazy-load-authentication-memberships.md)). The zeebe engine carries a parallel
implementation (`AuthorizationCheckBehavior`) for the same logical purpose, backed by RocksDB
state instead of the secondary index. To avoid two diverging evaluators, the engine should use
the CSL framework. Five gaps prevent that:

1. **Richer failure type** — the engine needs *why* a check failed (tenant vs. permission);
   `boolean` does not carry this.
2. **Tenant access check** — is the principal assigned to the tenant owning a resource?
   Not in the current model.
3. **Property-based authorization** — access based on resource properties (e.g. user-task
   `assignee`, `candidateUsers`, `candidateGroups`). No equivalent in the scope-based checker.
4. **Spring-free claims converter** — the engine has raw `Map<String,Object>` claims and no
   Spring context; the starter's converter cannot be used.
5. **Skip-checks query** — are checks globally disabled (authz and multi-tenancy off)?
   Needed to short-circuit the command hot path.

This ADR records how those gaps are filled with general-purpose additions that benefit both layers.

## Decision

### 1. No new Maven module

All additions land in `core`, which is already Spring-free (enforced by `DomainArchTest`).
A dedicated module may be split out later if `core` grows too large (see Alternatives).

### 2. Introduce `AuthorizationCheckPort` (`core/port/in/`) as the unified inbound port

One inbound port covers scope-based, tenant, and property-based checks for both layers.
Checks return `Either<AuthorizationRejection, Void>` instead of `boolean`, carrying the denial
reason. Property-based checks use the 3-arg overload
`<T> Either<AuthorizationRejection, Void> check(CamundaAuthentication, RequiredAuthorization<T>, T)`,
lifted from the concrete `AuthorizationService` onto the port so consumers never need the
concrete class. `skipChecks()` is deliberately **not** lifted onto the port — it is a concrete
hot-path convenience with no consumer calling it through the interface (YAGNI).

Signatures reuse the existing `CamundaAuthentication` and `RequiredAuthorization<T>` types; any
extension of `RequiredAuthorization<T>` (tenant context, resource properties) stays
general-purpose. Exact API shape is an Inc 1 implementation decision.

### 3. Add general-purpose failure types to `core`

- `Either<L, R>` — simple two-variant sealed type (replaces `io.camunda.zeebe.util.Either`)
- `AuthorizationRejection` with subtypes `Tenant` (not assigned to required tenant) and
  `Permission` (lacks required resource permission) — the two logical reasons any CSL check
  can fail, regardless of storage layer
- `RejectionAggregator` — composes multiple rejections into one (e.g. OR-semantics checks)

### 4. Add `PropertyAuthorizationEvaluator<T>` interface to `core`

General-purpose evaluator for property-based authorization; concrete evaluators register via
`PropertyAuthorizationEvaluatorRegistry`. Evaluators that inspect engine-internal resource
structures (e.g. `UserTaskPropertyAuthorizationEvaluator`) stay in `zeebe/engine`.

### 5. Add `LazyTokenClaimsConverter` to `core`

A Spring-free converter: claims map + `MembershipPort` → `CamundaAuthentication` with
lazily-resolved membership chains (same `Supplier`-based wiring as ADR-0011). The starter no
longer carries a parallel implementation; `OidcTokenAuthenticationConverter` wraps the core
class and translates `IllegalArgumentException` to `OAuth2AuthenticationException` at the
Spring boundary.

Claims→authentication conversion is exposed as inbound port `TokenClaimsAuthenticationResolver`
(`api/context`): `CamundaAuthentication resolve(Map<String,Object> claims)`.
`LazyTokenClaimsConverter` implements it, delegating to the pre-existing `convert(Map)` so
existing callers are untouched. The port lives in `api` so non-Spring consumers get a
framework-free surface and never name the concrete converter. It is deliberately not modelled
on `CamundaAuthenticationConverter<T>` (`supports`/`convert`): that contract probes a
framework-specific authentication object; this port unconditionally resolves an
already-extracted claims map.

**Dual-path group resolution**: the engine's `MembershipPort.groupIds()` adapter must check
`Authorization.USER_GROUPS_CLAIMS` in the claims first, falling back to `MembershipState`
(matching `ClaimsExtractor`'s existing behaviour).

### 6. Add `AuthorizationService` to `core` as the default `AuthorizationCheckPort` implementation

`AuthorizationService` orchestrates: **(a)** scope-based checks via `AuthorizationChecker`,
mapping the `boolean` result to `AuthorizationRejection.Tenant`/`.Permission`; **(b)**
property-based checks via the registered `PropertyAuthorizationEvaluator<T>` — a separate
evaluation path that must be documented in the class; **(c)** a `skipChecks()` query returning
`true` when both authz and multi-tenancy are globally disabled.

In the starter, `AuthorizationConfiguration` wires the service as a
`@ConditionalOnMissingBean` Spring bean. The zeebe engine is not a Spring context
([ADR-0008](0008-no-spring-boot-auto-configuration.md)), so graph assembly is captured in a
plain-Java factory `AuthorizationPortsFactory` (`core/authz`). Its sole public method
`create(...)` takes the outbound ports, the evaluator list, the config flags, and the claim
configuration (`usernameClaim`/`clientIdClaim`/`preferUsernameClaim`, optional
`MembershipResolutionContextPropagator`), builds the whole graph, and returns an
`AuthorizationPorts` holder exposing only `AuthorizationCheckPort checkPort()` and
`TokenClaimsAuthenticationResolver claimsResolver()` — backed by the **same** converter
instance, mirroring the Spring wiring. A non-Spring consumer therefore depends only on
`api` + `port/in` and never names a `core`-internal type. A static factory (not a builder) is
used because the argument set is small, fixed, and fully required.

The three starter `@Configuration` classes do **not** route through the factory — each
constructs its bean directly, keeping every bean separately `@ConditionalOnMissingBean`-
overridable (a host's custom `AuthorizationChecker` still flows into the service). The factory
publishes no granular `new*` methods: they would put `AuthorizationChecker` /
`AuthorizationService` / `LazyTokenClaimsConverter` back onto a public API surface — exactly
what this decision removes. The trivial per-`new` assembly therefore exists twice (factory and
starter beans), accepted deliberately.

### 7. Reuse `MembershipPort` + `AuthorizationScopeRepositoryPort` as unified outbound ports

No new outbound ports. The engine provides RocksDB-backed implementations of both. Verified
against the zeebe source: `AuthorizationScopeResolver.getScopesForEntity()` resolves scopes
via direct + roles + groups, mapping to `MembershipPort.roleIds()`/`groupIds()` chains; the
resolved owner-ID set matches `AuthorizationScopeRepositoryPort`'s existing
`Map<EntityType, Set<String>>` contract
([ADR-0022](0022-resource-access-control-framework-ownership.md)). `MappingRuleMatcher`
already bridges both layers — no migration needed. The search layer keeps its adapters unchanged.

**Caching** is an adapter-layer concern: the engine's RocksDB adapters cache internally
(Guava `LoadingCache`), keeping `core` dependency-free. This moves caching from per-request to
per-adapter; Inc 4 must verify equivalent performance via the existing authorization benchmark
(baseline from Inc 0b).

### 8. `ResourcePermissionPort` transition

Originally kept for backwards compatibility, with the caller migration deferred. Completed in
#399: the webapp authorization filter (`WebAppAuthorizationCheckFilter`) — the last consumer of
`ResourcePermissionPort` — was rerouted to `AuthorizationCheckPort.check(...)`, and the
`ResourcePermissionPort` inbound port, its `ResourcePermissionService` default, and the paired
`AuthorizationRepositoryPort` outbound port were all removed (ADR-0007, now superseded). The
delegation-to-`AuthorizationService` intermediate step proved unnecessary — the filter binds to
`AuthorizationCheckPort` directly.

## Consequences

**Positive**

- Single scope-evaluation kernel shared by both layers; semantic drift structurally prevented.
- No new Maven module or outbound port contracts; the engine implements two focused RocksDB
  adapters against existing ports.
- `Either`, `AuthorizationRejection`, and property-based checks are general-purpose port
  contract features, available to any consumer (search layer benefits once it migrates).
- A non-Spring consumer (zeebe engine, camunda/camunda#56803) depends only on `api` + `port/in`
  plus the factory entry point — never on `core`-internal types. Graph assembly is defined once;
  Spring and non-Spring paths build it identically.
- `LazyTokenClaimsConverter` makes raw-claims-to-auth conversion available to any non-Spring
  CSL consumer.

**Negative / accepted trade-offs**

- `core` grows with new (all general-purpose) types; extract a module later if it feels large.
- `PropertyAuthorizationEvaluator` is a second evaluation path inside `AuthorizationService`;
  callers must not bypass it — document explicitly in the class.
- Changes to `LazyTokenClaimsConverter`'s constructor or `convert()` must also update the
  `OidcTokenAuthenticationConverter` wrapper.
- No caching in `core`: engine per-command performance relies on adapter caches — Inc 4 must
  treat this as a required concern.
- `MembershipPort.groupIds()` adapter must implement the dual claims/`MembershipState` path —
  document in Inc 4 acceptance criteria.
- `AuthorizationCheckPort` gains an abstract method (3-arg property check); every hand-rolled
  implementer must provide it (in-repo test doubles updated).
- The per-`new` assembly is duplicated between `AuthorizationPortsFactory.create(...)` and the
  starter beans — accepted; the alternative (public granular `new*` methods) would leak
  `core`-internal types.

## Alternatives Considered

- **Separate engine-authz module with new port contracts.** Rejected — duplicates
  `AuthorizationChecker`; a new `IdentityStatePort` is superseded by the existing outbound ports.
- **Split `core` into `authz-core` + `authn-core`.** Deferred — the engine needs both concepts;
  the split adds Maven overhead with no hygiene gain at current scale.
- **Keep the engine's `AuthorizationCheckBehavior` as a parallel evaluator.** Rejected — the
  evaluators diverge over time; bugs fixed in one are not fixed in the other.
- **A builder on `AuthorizationService` instead of the plain-Java factory.** Rejected — the
  input set is fixed and required; a builder adds ceremony without solving anything.
- **Route the Spring `authorizationService` bean through `create(...)`.** Rejected — the factory
  would build its own checker/converter and silently discard host bean overrides.
- **Publish granular `new*` factory methods for the starter to reuse (DRY).** Rejected — exposes
  `core`-internal types on a public API surface; the duplicated one-line assembly is cheaper.
- **Reuse `CamundaAuthenticationConverter<T>` for claims resolution.** Rejected — its
  `supports`/`convert` shape targets framework-specific authentication objects, not a raw
  claims map.
- **Lift `skipChecks()` onto `AuthorizationCheckPort`.** Deferred — no consumer calls it through
  the port; speculative (YAGNI).
