/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.PermissionType;
import io.camunda.security.api.model.ResourceType;
import io.camunda.security.core.port.in.ResourcePermissionPort;
import io.camunda.security.core.port.out.AuthorizationRepositoryPort;

/**
 * Default {@link ResourcePermissionPort} implementation. Asks the host-supplied {@link
 * AuthorizationRepositoryPort} for the authorization records held by the principal on the requested
 * {@link ResourceType}, then returns {@code true} when any record matches the requested resource id
 * and carries the requested {@link PermissionType}.
 *
 * <p>Wildcard semantics (a grant on "all resources of this type") is not handled here yet — the
 * comparison is exact-id only. When a use case needs wildcard support, it can be added as a single
 * change to the matching predicate without affecting the host SPI.
 */
public final class ResourcePermissionService implements ResourcePermissionPort {

  private final AuthorizationRepositoryPort repository;

  public ResourcePermissionService(final AuthorizationRepositoryPort repository) {
    this.repository = repository;
  }

  @Override
  public boolean hasPermission(
      final CamundaAuthentication authentication,
      final ResourceType resourceType,
      final String resourceId,
      final PermissionType permissionType) {
    return repository.findAuthorizations(authentication, resourceType).stream()
        .anyMatch(
            authorization ->
                authorization.resourceId().equals(resourceId)
                    && authorization.permissionTypes().contains(permissionType));
  }
}
