/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.mockito.Mockito.verify;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import io.camunda.security.core.port.out.AuthorizationManagementRepositoryPort;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
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

    verify(repository)
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

    verify(repository)
        .revoke(
            AuthorizationOwnerType.ROLE,
            "admin-role",
            ResourceType.USER,
            "*",
            Set.of(PermissionType.READ, PermissionType.UPDATE));
  }
}
