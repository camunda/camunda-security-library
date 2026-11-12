/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** An in-memory grant store for tests, in which only roles hold grants. */
final class InMemoryGrants implements AuthorizationScopeRepositoryPort {

  private final List<Grant> grants = new ArrayList<>();

  void grant(
      final String roleId,
      final AuthorizationResourceType resourceType,
      final PermissionType permissionType,
      final AuthorizationScope scope) {
    grants.add(new Grant(roleId, resourceType, permissionType, scope));
  }

  @Override
  public List<AuthorizationScope> findAuthorizedScopes(
      final Map<EntityType, Set<String>> ownerIds,
      final AuthorizationResourceType resourceType,
      final PermissionType permissionType) {
    return grants.stream()
        .filter(grant -> grant.heldBy(ownerIds) && grant.covers(resourceType, permissionType))
        .map(Grant::scope)
        .toList();
  }

  @Override
  public boolean hasAuthorizedScope(
      final Map<EntityType, Set<String>> ownerIds,
      final AuthorizationResourceType resourceType,
      final PermissionType permissionType,
      final List<String> resourceIds) {
    return findAuthorizedScopes(ownerIds, resourceType, permissionType).stream()
        .anyMatch(scope -> resourceIds.contains(scope.getResourceId()));
  }

  @Override
  public Set<PermissionType> findPermissionTypes(
      final Map<EntityType, Set<String>> ownerIds,
      final AuthorizationResourceType resourceType,
      final List<String> resourceIds) {
    return Set.of();
  }

  private record Grant(
      String roleId,
      AuthorizationResourceType resourceType,
      PermissionType permissionType,
      AuthorizationScope scope) {

    boolean heldBy(final Map<EntityType, Set<String>> ownerIds) {
      return ownerIds.getOrDefault(EntityType.ROLE, Set.of()).contains(roleId);
    }

    boolean covers(final AuthorizationResourceType type, final PermissionType permission) {
      return resourceType == type && permissionType == permission;
    }
  }
}
