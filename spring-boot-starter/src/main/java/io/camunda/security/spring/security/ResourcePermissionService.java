/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import io.camunda.security.core.port.in.ResourcePermissionPort;
import io.camunda.security.core.port.out.AuthorizationRepositoryPort;

/**
 * Default {@link ResourcePermissionPort} implementation. Asks the host-supplied {@link
 * AuthorizationRepositoryPort} for the authorization records held by the principal on the requested
 * {@link ResourceType}, then returns {@code true} when any record matches the requested resource id
 * and carries the requested {@link PermissionType}.
 *
 * <p>A grant whose {@code resourceId} equals {@value #WILDCARD_RESOURCE_ID} represents "all
 * resources of this type" and matches any concrete id. This aligns with the wildcard convention
 * used elsewhere on the platform (e.g. {@code io.camunda.security.impl.AuthorizationChecker}).
 */
public final class ResourcePermissionService implements ResourcePermissionPort {

  private static final String WILDCARD_RESOURCE_ID = "*";

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
                matchesResourceId(authorization.resourceId(), resourceId)
                    && authorization.permissionTypes().contains(permissionType));
  }

  private static boolean matchesResourceId(final String grantedResourceId, final String requested) {
    return WILDCARD_RESOURCE_ID.equals(grantedResourceId) || grantedResourceId.equals(requested);
  }
}
