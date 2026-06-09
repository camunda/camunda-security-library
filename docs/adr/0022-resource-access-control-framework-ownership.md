---
status: Accepted
---

# ADR-0022: Lift resource access control framework into CSL core

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

The resource access control framework — the types and interfaces that translate a `SecurityContext`
into query-level `ResourceAccessChecks` — lived in OC's `security-core` module (`reader/` package)
alongside the authorization checker service in `security-services`. These classes enable the
`ResourcePermissionPort` and `TenantPort` contracts declared in CSL by providing the query-filter
model that search/reader backends use to scope results to authorized resources.

Additionally, `AuthorizationChecker` (the service that queries the authorization store to resolve
which resource scopes a principal may access) coupled `security-services` directly to OC's
search-layer `AuthorizationReader`, preventing migration to CSL without introducing a search
dependency in CSL's domain.

This is Increment 15 of the ongoing migration of OC security concerns into the Camunda Security
Library. [ADR-0019](0019-authorization-runtime-check-migration-and-no-jackson-in-domain.md) established the `RequiredAuthorization<T>` naming (formerly `Authorization<T>`)
that the reader framework and checker operate on.

The core question: should the reader framework and authorization checker live in OC (where their
callers and implementations live) or in CSL (where the port contracts they support are defined)?

## Decision

1. The 8 reader-framework classes (`AuthorizationCheck`, `ResourceAccess`, `ResourceAccessChecks`,
   `ResourceAccessController`, `ResourceAccessProvider`, `TenantAccess`, `TenantAccessProvider`,
   `TenantCheck`) are moved to CSL `core` under `io.camunda.security.core.authz`. All references
   to `Authorization<T>` are updated to `RequiredAuthorization<T>` (the Inc 14 rename).

2. A new outbound port `AuthorizationScopeRepositoryPort` is introduced in CSL
   `core/port/out`. It abstracts the three query patterns `AuthorizationChecker` needs:
   `findAuthorizedScopes`, `hasAuthorizedScope`, and `findPermissionTypes`. The port receives
   pre-resolved owner-type-to-ids maps so it does not depend on `CamundaAuthentication` directly.

3. `AuthorizationChecker` is moved to CSL `core/authz`, rewritten against
   `AuthorizationScopeRepositoryPort`, and updated to use `RequiredAuthorization<T>`.

4. CSL `spring-boot-starter` ships `AuthorizationCheckerConfiguration` (in
   `io.camunda.security.spring.authz`) conditional on `AuthorizationScopeRepositoryPort` being
   present. It is registered in the `CamundaSecurityAutoConfiguration` umbrella.

5. OC provides `SearchAuthorizationScopeRepository` in `security-services`, backed by
   `AuthorizationReader`, as the implementation of `AuthorizationScopeRepositoryPort`. OC's
   `dist/AuthorizationScopeRepositoryConfiguration` imports CSL's
   `AuthorizationCheckerConfiguration` and registers the port implementation.

### Why these particular boundaries

- **Reader framework belongs in CSL**: the classes are pure value types and interfaces with no
  OC-specific dependencies — they only reference `CamundaAuthentication` and `RequiredAuthorization`,
  both already in CSL. Keeping them in OC creates an asymmetry where CSL's port contracts reference
  types defined outside CSL.

- **Port instead of direct `AuthorizationReader` reference**: `AuthorizationReader` is an OC search
  abstraction. Putting it in the `AuthorizationChecker` constructor would drag a search dependency
  into CSL's domain layer, which ArchUnit enforces to be framework-free. The port pattern is the
  standard CSL resolution: domain defines the contract, host provides the implementation.

- **Three methods on one port instead of three ports**: all three query patterns share the same
  owner-id resolution context and the same backing store. Splitting them into separate ports would
  create artificial seams with no architectural benefit.

- **`@ConditionalOnBean` rather than `@ConditionalOnMissingBean`**: the `AuthorizationChecker` bean
  should only activate when the host explicitly provides the port. A host that does not provide
  `AuthorizationScopeRepositoryPort` has not opted in to the authorization checking stack.

## Consequences

**Positive**

- OC's `security-core/reader/` package and `security-services/AuthorizationChecker` are deleted;
  CSL owns both the framework and the checker.
- `search-client` module gains `camunda-security-library-core` dependency to replace its former
  dependency on `security-core` for reader types.
- Future host implementations of the reader framework implement CSL interfaces directly with no OC
  dependency required.
- `AuthorizationChecker` unit tests no longer require OC search plumbing — the port is mocked.

**Negative / accepted trade-offs**

- OC's `dist/AuthorizationCheckerConfiguration` must be renamed to
  `AuthorizationScopeRepositoryConfiguration` to avoid a simple-name collision with CSL's
  `AuthorizationCheckerConfiguration`.
- All `io.camunda.security.reader.*` imports in OC become `io.camunda.security.core.authz.*`,
  requiring a bulk import update across several OC modules.

## Alternatives Considered

- **Keep everything in OC.** Rejected — the reader framework has no OC-specific dependencies and
  CSL's port contracts reference these types; keeping them in OC inverts the dependency direction.
- **Introduce a separate `security-reader` CSL module.** Rejected — the framework is lightweight
  (8 classes, no new dependencies) and belongs naturally in `core` alongside the port contracts it
  supports. A new module would add Maven overhead with no benefit at this scale.
- **Make `AuthorizationScopeRepositoryPort` part of the public `api/` module.** Rejected — the
  port is an infrastructure contract for host implementors of the search/persistence layer, not a
  model type consumer-facing adopters import directly. The `core/port/out/` placement matches the
  existing pattern for outbound ports.
