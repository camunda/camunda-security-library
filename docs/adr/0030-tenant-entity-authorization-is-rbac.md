---
status: Accepted
---

# ADR-0030: Tenant-entity authorization is RBAC gated on authorizationEnabled

**Deciders**: Patrick Wunderlich

## Status

Accepted

Clarifies the gating contract of the `AuthorizationCheckPort.check(...)` surface introduced by
[ADR-0028](0028-unified-authz-framework-in-core.md). ADR-0028 stands unchanged; this ADR records a
correctness decision about how the `TENANT` resource type is gated.

## Context

`AuthorizationService` (the default `AuthorizationCheckPort`) was extracted from Orchestration
Cluster's `AuthorizationCheckBehavior`. The extraction derived a single discriminator,
`isTenantCheck = resourceType == TENANT`, and used it to route **all** `TENANT`-typed checks to the
`multiTenancyChecksEnabled` gate. That conflated two independent concerns:

1. **RBAC on tenant *entities*** — create / update / delete a tenant, add / remove a member. This is
   an authorization concern and must be gated on `authorizationEnabled`.
2. **Tenant *membership*** — "may this principal act within tenant X". This is the only concern that
   belongs on the `multiTenancyChecksEnabled` gate.

The conflation produced a bidirectional defect
([#486](https://github.com/camunda/camunda-security-library/issues/486)):

| authorizations | multi-tenancy | Tenant management op | Behaviour |
|---|---|---|---|
| ON | OFF | authorized for anyone (check skipped) | **fail-open** — privilege-escalation shape |
| OFF | ON | rejected (scope check runs) | **fail-closed** regression |

Tracing the actual callers (the User/Tenant processor migration in camunda/camunda#56781) settled
the question of how membership flows through the port:

- All tenant-management processors call
  `permissionsBehavior.isAuthorized(command, PermissionType.X, AuthorizationResourceType.TENANT)`,
  which builds `RequiredAuthorization.of(b -> b.resourceType(TENANT).permissionType(X).resourceId("*"))`.
  The resource ID is **always the wildcard `"*"`** — never a tenant ID to validate membership against.
- Tenant membership is a **separate dimension** in CSL (`TenantAccessProvider` / `TenantCheck` /
  `CamundaAuthentication.authenticatedTenantIds`) and does **not** flow through
  `AuthorizationCheckPort.check(...)`.

So every check routed through `check(auth, RequiredAuthorization)` — including `resourceType==TENANT`
— is RBAC.

## Decision

`AuthorizationService.check(auth, RequiredAuthorization)` gates **all** checks, including
`resourceType == TENANT`, on `authorizationEnabled`. `resourceType == TENANT` denotes RBAC on tenant
entities. `multiTenancyChecksEnabled` no longer participates in the per-check gate; it remains a
constructor input solely for `skipChecks()` (the "both globally disabled" hot-path query).

**Forward-looking rule:** future tenant-*membership* checks must **not** be expressed as
`check(auth, RequiredAuthorization)` with `resourceType == TENANT` expecting multi-tenancy gating.
Membership stays with `TenantAccessProvider` / `TenantCheck`. If membership ever needs to flow
through this port, it must be modelled as an explicit dimension on `RequiredAuthorization` (e.g. a
tenant ID to validate) rather than inferred from the resource type. Adding that dimension now would
be speculative and unused (YAGNI); it is deferred until a caller needs it.

**Non-goal:** a failed `TENANT` RBAC check continues to return `AuthorizationRejection.Tenant`
(not `AuthorizationRejection.Permission`). Both map to HTTP 403; keeping the label avoids gratuitous
cross-repo message churn (engine tests assert the tenant message). Re-labelling to `Permission` is a
separate cross-repo concern, out of scope here.

## Consequences

**Positive**

- Both rows of the #486 defect table are fixed: tenant management RBAC is enforced whenever
  `authorizationEnabled`, and is not spuriously rejected when authorizations are off.
- The gate for `TENANT` is now identical to every other resource type — one rule, no special case.
- The redundant `skipChecks()` call in the property-based `check(...)` overload
  (`skipChecks() || !authorizationEnabled` ≡ `!authorizationEnabled`) is removed at the same time.

**Negative / accepted trade-offs**

- `multiTenancyChecksEnabled` becomes near-vestigial in `AuthorizationService` (used only by
  `skipChecks()`). This reflects reality: membership-via-port is not implemented. The field and the
  query are retained deliberately.
- Behaviour the engine observes changes: engine tests that passed only because the check was skipped
  (authz ON / multi-tenancy OFF) will now correctly see a 403. camunda/camunda#56781 is the vehicle
  to absorb those expectation updates.

## Alternatives Considered

- **Discriminate membership by `resourceType==TENANT && permissionType==READ`.** Rejected — a guess
  that merely preserves the two pre-existing tests; reintroduces the same silent-assumption bug class
  if `TENANT:READ` ever means an RBAC read of tenant configuration.
- **Add an explicit tenant-membership field to `RequiredAuthorization` now.** Deferred — no caller
  routes membership through the port today (all callers pass `resourceId="*"`), so the field would be
  unused. Recorded as the required shape *if* membership is later moved onto the port.
