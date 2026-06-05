---
status: Accepted
---

# ADR-0020: Migrate `SecurityContext` and authorization-condition types to CSL; seal `AuthorizationCondition`

**Deciders**: @p-wunderlich

## Status

Accepted

## Context

[ADR-0019](0019-authorization-runtime-check-migration-and-no-jackson-in-domain.md) migrated
OC's `Authorization<T>` runtime check spec to CSL as `RequiredAuthorization<T>`. The remaining
classes in OC's `security-core/auth/` that depend on it are:

| OC class | Role |
|---|---|
| `SecurityContext` | Bundles authentication + authorization condition for an operation |
| `AuthorizationCondition` | Sealed sum type: single or any-of authorization check |
| `SingleAuthorizationCondition` | Wraps exactly one `RequiredAuthorization` |
| `AnyOfAuthorizationCondition` | Disjunctive: access when any child is satisfied |
| `AuthorizationConditions` | Factory helpers |
| `BrokerRequestAuthorizationConverter` | Converts `CamundaAuthentication` → broker claim map |

This decision covers the first five. `BrokerRequestAuthorizationConverter` is host-specific
(depends on Zeebe claim keys and engine security config) and stays in OC.

## Decision

### 1. Migrate `SecurityContext` and the four condition types to `core/auth/`

All four condition types and `SecurityContext` are pure domain logic: they depend only on
`RequiredAuthorization`, `CamundaAuthentication`, and standard Java. They have no framework,
Zeebe, or Jackson dependencies, so they land cleanly in `core/` without violating any ArchUnit
boundary.

`SecurityContext`'s Jackson annotations (`@JsonAutoDetect`, `@JsonProperty`) are stripped
following the same policy established in ADR-0019: hosts that need custom serialization of CSL
types register a Jackson mixin on their own `ObjectMapper`.

### 2. Seal `AuthorizationCondition`

OC's `AuthorizationCondition` is an open interface, but its sole `default` method
(`authorizations()`) already pattern-matches on exactly two concrete record types and throws
`IllegalStateException` for anything else. This is a sealed type in everything but the keyword.

We make it explicit by declaring `sealed interface AuthorizationCondition permits
SingleAuthorizationCondition, AnyOfAuthorizationCondition`. Benefits:

- Compiler enforces exhaustiveness at switch/pattern-match sites — no runtime `IllegalStateException`.
- Documents the contract: callers and implementers know the full set of subtypes.
- Prevents third-party implementations that the `authorizations()` default method would not handle.

The `IllegalStateException` branch in `authorizations()` is kept as a sealed fallthrough guard
(Java requires the default to compile), but it can never be reached in practice.

### 3. Exclude `BrokerRequestAuthorizationConverter`

`BrokerRequestAuthorizationConverter` depends on `io.camunda.zeebe.auth.Authorization` claim
key constants (a Zeebe wire-protocol contract) and on OC's `EngineSecurityConfig`. Adding
Zeebe claim key constants or a Zeebe runtime dependency to CSL's framework-free `core/` would
widen the dependency surface of the library beyond its identity-and-authorization scope. The
class stays in OC's `security-core` where those dependencies are already present.

## Consequences

- OC can remove its local copies of `SecurityContext`, `AuthorizationCondition`,
  `SingleAuthorizationCondition`, `AnyOfAuthorizationCondition`, and `AuthorizationConditions`
  after upgrading to the CSL release that contains this change.
- OC's `SecurityContext.Builder.withAuthorization(Authorization<?> ...)` calls become
  `.withAuthorization(RequiredAuthorization<?> ...)` following the rename from ADR-0019.
- `BrokerRequestAuthorizationConverter` stays in OC and continues to import OC-local types.
- Third-party code that subclasses `AuthorizationCondition` will see a compile error when
  upgrading — this is intentional; the type was never meant to be extended.
