/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.authz.AuthorizationResourceMatcher;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** An in-memory grant store for tests of the evaluation of grants. */
final class InMemoryAuthorizationStore implements AuthorizationScopeRepositoryPort {

  private final List<Grant> grants = new ArrayList<>();
  private int scopeQueries;

  InMemoryAuthorizationStore grant(
      final EntityType ownerType,
      final String ownerId,
      final AuthorizationResourceType resourceType,
      final PermissionType permissionType,
      final AuthorizationScope scope) {
    grants.add(new Grant(ownerType, ownerId, resourceType, permissionType, scope));
    return this;
  }

  InMemoryAuthorizationStore roleGrant(
      final String roleId,
      final AuthorizationResourceType resourceType,
      final PermissionType permissionType,
      final AuthorizationScope scope) {
    return grant(EntityType.ROLE, roleId, resourceType, permissionType, scope);
  }

  InMemoryAuthorizationStore userGrant(
      final String username,
      final AuthorizationResourceType resourceType,
      final PermissionType permissionType,
      final AuthorizationScope scope) {
    return grant(EntityType.USER, username, resourceType, permissionType, scope);
  }

  /** The number of times grants were looked up by owner. */
  int scopeQueries() {
    return scopeQueries;
  }

  @Override
  public List<AuthorizationScope> findAuthorizedScopes(
      final Map<EntityType, Set<String>> ownerIds,
      final AuthorizationResourceType resourceType,
      final PermissionType permissionType) {
    scopeQueries++;
    return grants.stream()
        .filter(grant -> grant.isOwnedBy(ownerIds))
        .filter(grant -> grant.resourceType() == resourceType)
        .filter(grant -> grant.permissionType() == permissionType)
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
        .filter(scope -> scope.getMatcher() != AuthorizationResourceMatcher.PROPERTY)
        .anyMatch(scope -> resourceIds.contains(scope.getResourceId()));
  }

  @Override
  public Set<PermissionType> findPermissionTypes(
      final Map<EntityType, Set<String>> ownerIds,
      final AuthorizationResourceType resourceType,
      final List<String> resourceIds) {
    throw new UnsupportedOperationException();
  }

  private record Grant(
      EntityType ownerType,
      String ownerId,
      AuthorizationResourceType resourceType,
      PermissionType permissionType,
      AuthorizationScope scope) {

    boolean isOwnedBy(final Map<EntityType, Set<String>> ownerIds) {
      return ownerIds.getOrDefault(ownerType, Set.of()).contains(ownerId);
    }
  }
}
