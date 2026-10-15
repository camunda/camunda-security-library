# Authorization Management Ports — Design

**Issue:** [#464](https://github.com/camunda/camunda-security-library/issues/464)
**Date:** 2026-07-30
**Parent feature:** [#348](https://github.com/camunda/camunda-security-library/issues/348)

## Context

Hub needs to assign and revoke resource authorizations via CSL. This task adds the port layer: an inbound port Hub calls, a passthrough service, and an outbound port Hub's adapter will satisfy by delegating to Management Identity. No callers or adapter implementations are included here.

## Files

### `core/src/main/java/io/camunda/security/core/port/in/AuthorizationManagementPort.java`

Inbound port Hub calls to assign and revoke authorizations. Expressed entirely in CSL domain types.

```java
public interface AuthorizationManagementPort {
  void assign(AuthorizationOwnerType ownerType, String ownerId,
              ResourceType resourceType, String resourceId,
              Set<PermissionType> permissionTypes);
  void revoke(AuthorizationOwnerType ownerType, String ownerId,
              ResourceType resourceType, String resourceId,
              Set<PermissionType> permissionTypes);
}
```

### `core/src/main/java/io/camunda/security/core/port/out/AuthorizationManagementRepositoryPort.java`

Outbound port mirroring the inbound port. Hub satisfies this with an adapter that delegates to Management Identity (issue #467).

Same two method signatures as the inbound port.

### `core/src/main/java/io/camunda/security/core/authz/AuthorizationManagementService.java`

`final` class implementing `AuthorizationManagementPort`. Constructor-injected `AuthorizationManagementRepositoryPort`. Each method delegates directly to the outbound port — no logic, no configuration flags.

Placed in `core/` (not `spring-boot-starter/`) because it has no Spring dependencies.

### `core/src/test/java/io/camunda/security/core/authz/AuthorizationManagementServiceTest.java`

Unit tests using `@ExtendWith(MockitoExtension.class)`, `@Mock AuthorizationManagementRepositoryPort`, `@InjectMocks AuthorizationManagementService`.

Two tests:
- `assign(...)` delegates to the outbound port with the same arguments
- `revoke(...)` delegates to the outbound port with the same arguments

## Constraints

- No Spring annotations anywhere — `DomainArchTest` must pass
- No starter configuration bean or `@ConditionalOnMissingBean` needed at this stage
- Individual parameters chosen over a command record for consistency with `ResourcePermissionPort`
