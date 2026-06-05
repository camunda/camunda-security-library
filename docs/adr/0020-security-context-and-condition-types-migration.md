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
| `AuthorizationCondition` | Sum type: single or any-of authorization check |
| `SingleAuthorizationCondition` | Wraps exactly one `RequiredAuthorization` |
| `AnyOfAuthorizationCondition` | Disjunctive: access when any child is satisfied |
| `AuthorizationConditions` | Factory helpers |
| `BrokerRequestAuthorizationConverter` | Converts `CamundaAuthentication` → broker claim map |

This decision covers the first five. `BrokerRequestAuthorizationConverter` is host-specific
(depends on Zeebe claim keys and engine security config) and stays in OC.

## Decision

Migrate `SecurityContext`, `AuthorizationCondition`, `SingleAuthorizationCondition`,
`AnyOfAuthorizationCondition`, and `AuthorizationConditions` to `io.camunda.security.core.auth`
and `io.camunda.security.core.auth.condition`.

### Seal `AuthorizationCondition`

OC's `AuthorizationCondition` is an open interface, but its sole `default` method
(`authorizations()`) already pattern-matches on exactly two concrete record types and throws
`IllegalStateException` for anything else. This is a sealed type in everything but the keyword.

We make it explicit: `sealed interface AuthorizationCondition permits
SingleAuthorizationCondition, AnyOfAuthorizationCondition`. The compiler enforces exhaustiveness
at switch/pattern-match sites; third-party subtypes that the `authorizations()` default cannot
handle are rejected at compile time rather than at runtime.

### Strip Jackson annotations from `SecurityContext`

`SecurityContext`'s `@JsonAutoDetect` and `@JsonProperty` annotations are removed following the
same policy established in ADR-0019: hosts that need custom serialization register a Jackson mixin
on their own `ObjectMapper`.

### Exclude `BrokerRequestAuthorizationConverter`

`BrokerRequestAuthorizationConverter` depends on `io.camunda.zeebe.auth.Authorization` claim key
constants (a Zeebe wire-protocol contract) and on OC's `EngineSecurityConfig`. These are
host-specific dependencies that do not belong in CSL's framework-free `core/` module. The class
stays in OC's `security-core`.

## Consequences

**Positive**

- OC can remove five classes from `security-core/auth/` after upgrading to the CSL release that
  contains this change.
- `AuthorizationCondition` subtypes are now compiler-verified exhaustive — pattern-match sites
  cannot miss a case without a compile error.
- CSL's domain boundary remains Jackson-free and Zeebe-free.

**Negative / accepted trade-offs**

- Third-party code that subclasses `AuthorizationCondition` will see a compile error when
  upgrading — intentional; the type was never designed for extension.
- `BrokerRequestAuthorizationConverter` remains in OC, so the OC integration PR still has one
  class with an OC-local import. This is preferable to widening CSL's dependency surface.
- OC's `SecurityContext.Builder.withAuthorization(Authorization<?> ...)` call sites must be
  updated to `withAuthorization(RequiredAuthorization<?> ...)` following the rename from ADR-0019.

## Alternatives Considered

- **Keep `AuthorizationCondition` as an open interface.** Rejected — the existing `default
  authorizations()` method throws `IllegalStateException` for any unknown subtype, meaning third-party
  implementations silently break at runtime. Sealing makes this a compile-time error.
- **Migrate `BrokerRequestAuthorizationConverter` to CSL `core/` by replicating Zeebe claim key
  constants.** Rejected — CSL is an identity-and-authorization library; owning Zeebe wire-protocol
  claim keys couples it to the broker's serialization format. The converter and its constants stay
  in OC where that coupling already exists.
