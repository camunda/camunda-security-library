# Authorization Management Ports Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `AuthorizationManagementPort` (inbound), `AuthorizationManagementRepositoryPort` (outbound), and `AuthorizationManagementService` (passthrough) to CSL core — the port layer Hub will wire through in a follow-on task.

**Architecture:** Pure interface and service additions in `core/`; no framework dependencies. The service delegates every call directly to the outbound port with no transformation or logic. No Spring wiring is introduced at this stage.

**Tech Stack:** Java 21, JUnit 5, Mockito (`mockito-junit-jupiter`), AssertJ, ArchUnit (existing — must continue to pass)

## Global Constraints

- All new production classes in `core/` must have zero Spring, Jakarta Servlet, Jakarta Persistence, Jackson, or zeebe-protocol dependencies — enforced by `DomainArchTest`
- All production classes must be `final` (no extension points introduced here)
- No `*Impl` suffix — implementations are named by responsibility
- Port interfaces live in `port/in/` (inbound) and `port/out/` (outbound)
- Service implementation lives in `core/authz/` (framework-free, consistent with `AuthorizationService`)
- All new classes must have corresponding tests before committing
- License header required on every new file (see below)

### License header (copy verbatim onto every new file)

```
/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
```

---

## File Map

| Action | Path |
|--------|------|
| Create | `core/src/main/java/io/camunda/security/core/port/in/AuthorizationManagementPort.java` |
| Create | `core/src/main/java/io/camunda/security/core/port/out/AuthorizationManagementRepositoryPort.java` |
| Create | `core/src/main/java/io/camunda/security/core/authz/AuthorizationManagementService.java` |
| Create | `core/src/test/java/io/camunda/security/core/authz/AuthorizationManagementServiceTest.java` |

---

## Task 1: Define the two port interfaces

**Files:**
- Create: `core/src/main/java/io/camunda/security/core/port/in/AuthorizationManagementPort.java`
- Create: `core/src/main/java/io/camunda/security/core/port/out/AuthorizationManagementRepositoryPort.java`

**Interfaces:**
- Produces (for Task 2):
  - `AuthorizationManagementPort` — inbound interface with `void assign(...)` and `void revoke(...)`
  - `AuthorizationManagementRepositoryPort` — outbound interface with identical signatures

- [ ] **Step 1: Create the inbound port**

`core/src/main/java/io/camunda/security/core/port/in/AuthorizationManagementPort.java`

```java
/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import java.util.Set;

/**
 * Inbound port for authorization management. Hub calls this to assign or revoke resource
 * authorizations for a given owner.
 */
public interface AuthorizationManagementPort {

  void assign(
      AuthorizationOwnerType ownerType,
      String ownerId,
      ResourceType resourceType,
      String resourceId,
      Set<PermissionType> permissionTypes);

  void revoke(
      AuthorizationOwnerType ownerType,
      String ownerId,
      ResourceType resourceType,
      String resourceId,
      Set<PermissionType> permissionTypes);
}
```

- [ ] **Step 2: Create the outbound port**

`core/src/main/java/io/camunda/security/core/port/out/AuthorizationManagementRepositoryPort.java`

```java
/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import java.util.Set;

/**
 * Outbound port for authorization management. Hub satisfies this with an adapter that delegates to
 * Management Identity (issue #467).
 */
public interface AuthorizationManagementRepositoryPort {

  void assign(
      AuthorizationOwnerType ownerType,
      String ownerId,
      ResourceType resourceType,
      String resourceId,
      Set<PermissionType> permissionTypes);

  void revoke(
      AuthorizationOwnerType ownerType,
      String ownerId,
      ResourceType resourceType,
      String resourceId,
      Set<PermissionType> permissionTypes);
}
```

- [ ] **Step 3: Compile to confirm no typos**

```bash
mvn compile -pl core -q
```

Expected: `BUILD SUCCESS` with no errors.

---

## Task 2: Implement `AuthorizationManagementService` (TDD)

**Files:**
- Create: `core/src/main/java/io/camunda/security/core/authz/AuthorizationManagementService.java`
- Create: `core/src/test/java/io/camunda/security/core/authz/AuthorizationManagementServiceTest.java`

**Interfaces:**
- Consumes (from Task 1):
  - `io.camunda.security.core.port.in.AuthorizationManagementPort`
  - `io.camunda.security.core.port.out.AuthorizationManagementRepositoryPort`
- Produces: `AuthorizationManagementService implements AuthorizationManagementPort`

- [ ] **Step 1: Create a no-op stub service so the test compiles**

`core/src/main/java/io/camunda/security/core/authz/AuthorizationManagementService.java`

```java
/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import io.camunda.security.core.port.in.AuthorizationManagementPort;
import io.camunda.security.core.port.out.AuthorizationManagementRepositoryPort;
import java.util.Set;

public final class AuthorizationManagementService implements AuthorizationManagementPort {

  private final AuthorizationManagementRepositoryPort repository;

  public AuthorizationManagementService(final AuthorizationManagementRepositoryPort repository) {
    this.repository = repository;
  }

  @Override
  public void assign(
      final AuthorizationOwnerType ownerType,
      final String ownerId,
      final ResourceType resourceType,
      final String resourceId,
      final Set<PermissionType> permissionTypes) {
    // not yet delegating
  }

  @Override
  public void revoke(
      final AuthorizationOwnerType ownerType,
      final String ownerId,
      final ResourceType resourceType,
      final String resourceId,
      final Set<PermissionType> permissionTypes) {
    // not yet delegating
  }
}
```

- [ ] **Step 2: Write the failing tests**

`core/src/test/java/io/camunda/security/core/authz/AuthorizationManagementServiceTest.java`

```java
/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import io.camunda.security.core.port.out.AuthorizationManagementRepositoryPort;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuthorizationManagementServiceTest {

  @Mock private AuthorizationManagementRepositoryPort repository;

  @InjectMocks private AuthorizationManagementService service;

  @Test
  void assignDelegatesToRepository() {
    service.assign(
        AuthorizationOwnerType.USER,
        "alice",
        ResourceType.PROCESS_DEFINITION,
        "my-process",
        Set.of(PermissionType.CREATE_PROCESS_INSTANCE));

    Mockito.verify(repository)
        .assign(
            AuthorizationOwnerType.USER,
            "alice",
            ResourceType.PROCESS_DEFINITION,
            "my-process",
            Set.of(PermissionType.CREATE_PROCESS_INSTANCE));
  }

  @Test
  void revokeDelegatesToRepository() {
    service.revoke(
        AuthorizationOwnerType.ROLE,
        "admin-role",
        ResourceType.USER,
        "*",
        Set.of(PermissionType.READ, PermissionType.UPDATE));

    Mockito.verify(repository)
        .revoke(
            AuthorizationOwnerType.ROLE,
            "admin-role",
            ResourceType.USER,
            "*",
            Set.of(PermissionType.READ, PermissionType.UPDATE));
  }
}
```

- [ ] **Step 3: Run tests — expect FAIL**

```bash
mvn test -pl core -Dtest=AuthorizationManagementServiceTest -q
```

Expected: two failures like:
```
Wanted but not invoked:
  repository.assign(USER, "alice", PROCESS_DEFINITION, "my-process", [...])
```

- [ ] **Step 4: Implement delegation in the service**

Replace the no-op method bodies in `AuthorizationManagementService` with delegation calls:

```java
  @Override
  public void assign(
      final AuthorizationOwnerType ownerType,
      final String ownerId,
      final ResourceType resourceType,
      final String resourceId,
      final Set<PermissionType> permissionTypes) {
    repository.assign(ownerType, ownerId, resourceType, resourceId, permissionTypes);
  }

  @Override
  public void revoke(
      final AuthorizationOwnerType ownerType,
      final String ownerId,
      final ResourceType resourceType,
      final String resourceId,
      final Set<PermissionType> permissionTypes) {
    repository.revoke(ownerType, ownerId, resourceType, resourceId, permissionTypes);
  }
```

The full file after this change:

```java
/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import io.camunda.security.core.port.in.AuthorizationManagementPort;
import io.camunda.security.core.port.out.AuthorizationManagementRepositoryPort;
import java.util.Set;

public final class AuthorizationManagementService implements AuthorizationManagementPort {

  private final AuthorizationManagementRepositoryPort repository;

  public AuthorizationManagementService(final AuthorizationManagementRepositoryPort repository) {
    this.repository = repository;
  }

  @Override
  public void assign(
      final AuthorizationOwnerType ownerType,
      final String ownerId,
      final ResourceType resourceType,
      final String resourceId,
      final Set<PermissionType> permissionTypes) {
    repository.assign(ownerType, ownerId, resourceType, resourceId, permissionTypes);
  }

  @Override
  public void revoke(
      final AuthorizationOwnerType ownerType,
      final String ownerId,
      final ResourceType resourceType,
      final String resourceId,
      final Set<PermissionType> permissionTypes) {
    repository.revoke(ownerType, ownerId, resourceType, resourceId, permissionTypes);
  }
}
```

- [ ] **Step 5: Run tests — expect PASS**

```bash
mvn test -pl core -Dtest=AuthorizationManagementServiceTest -q
```

Expected: `BUILD SUCCESS`, both tests green.

- [ ] **Step 6: Run full core test suite including ArchUnit**

```bash
mvn test -pl core -q
```

Expected: `BUILD SUCCESS`. This confirms `DomainArchTest` passes — the new service has no framework imports.

- [ ] **Step 7: Run spring-boot-starter tests to confirm no regressions**

```bash
mvn test -pl spring-boot-starter -q
```

Expected: `BUILD SUCCESS`.

- [ ] **Step 8: Apply Spotless formatting**

```bash
mvn spotless:apply -pl core -q
```

Expected: `BUILD SUCCESS`. Re-run the tests if Spotless reformatted anything:

```bash
mvn test -pl core -q
```

- [ ] **Step 9: Commit**

```bash
git add \
  core/src/main/java/io/camunda/security/core/port/in/AuthorizationManagementPort.java \
  core/src/main/java/io/camunda/security/core/port/out/AuthorizationManagementRepositoryPort.java \
  core/src/main/java/io/camunda/security/core/authz/AuthorizationManagementService.java \
  core/src/test/java/io/camunda/security/core/authz/AuthorizationManagementServiceTest.java
git commit -m "feat(authz): add AuthorizationManagementPort, repository port, and passthrough service"
```
