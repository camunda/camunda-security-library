/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AuthorizationScopeRepositoryPortTest {

  private static final AuthorizationScope ASSIGNEE_SCOPE = AuthorizationScope.property("assignee");
  private static final AuthorizationScope CANDIDATE_GROUPS_SCOPE =
      AuthorizationScope.property("candidateGroups");

  @Test
  void defaultFindAuthorizedPropertyScopesFiltersToDeclaredPropertyNames() {
    final var port = portBackedBy(List.of(ASSIGNEE_SCOPE, CANDIDATE_GROUPS_SCOPE));

    final var result =
        port.findAuthorizedPropertyScopes(
            Map.of(EntityType.USER, Set.of("alice")),
            AuthorizationResourceType.USER_TASK,
            PermissionType.READ_USER_TASK,
            Set.of("assignee"));

    assertThat(result).containsExactly(ASSIGNEE_SCOPE);
  }

  @Test
  void defaultFindAuthorizedPropertyScopesFiltersOutNonPropertyScopes() {
    final var port =
        portBackedBy(List.of(AuthorizationScope.id("task-1"), AuthorizationScope.WILDCARD));

    final var result =
        port.findAuthorizedPropertyScopes(
            Map.of(EntityType.USER, Set.of("alice")),
            AuthorizationResourceType.USER_TASK,
            PermissionType.READ_USER_TASK,
            Set.of("assignee"));

    assertThat(result).isEmpty();
  }

  @Test
  void defaultFindAuthorizedPropertyScopesReturnsEmptyWhenNoScopesMatch() {
    final var port = portBackedBy(List.of());

    final var result =
        port.findAuthorizedPropertyScopes(
            Map.of(EntityType.USER, Set.of("alice")),
            AuthorizationResourceType.USER_TASK,
            PermissionType.READ_USER_TASK,
            Set.of("assignee"));

    assertThat(result).isEmpty();
  }

  private static AuthorizationScopeRepositoryPort portBackedBy(
      final List<AuthorizationScope> scopes) {
    return new AuthorizationScopeRepositoryPort() {
      @Override
      public List<AuthorizationScope> findAuthorizedScopes(
          final Map<EntityType, Set<String>> ownerIds,
          final AuthorizationResourceType resourceType,
          final PermissionType permissionType) {
        return scopes;
      }

      @Override
      public boolean hasAuthorizedScope(
          final Map<EntityType, Set<String>> ownerIds,
          final AuthorizationResourceType resourceType,
          final PermissionType permissionType,
          final List<String> resourceIds) {
        throw new UnsupportedOperationException();
      }

      @Override
      public Set<PermissionType> findPermissionTypes(
          final Map<EntityType, Set<String>> ownerIds,
          final AuthorizationResourceType resourceType,
          final List<String> resourceIds) {
        throw new UnsupportedOperationException();
      }
    };
  }
}
