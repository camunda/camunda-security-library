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
