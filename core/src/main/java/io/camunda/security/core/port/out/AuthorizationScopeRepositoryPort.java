/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.api.model.authz.AuthorizationResourceMatcher;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Outbound port for authorization scope queries. The host implements this backed by its
 * authorization data store (e.g. a search index or relational table).
 *
 * <p>All methods receive a pre-resolved map of {@link EntityType} to owner IDs so the port does not
 * depend on {@link io.camunda.security.api.model.CamundaAuthentication} directly — the caller
 * (typically {@link io.camunda.security.core.authz.AuthorizationChecker}) is responsible for
 * extracting the relevant principal identities from the authentication object before invoking the
 * port.
 *
 * <p>The core query patterns {@code AuthorizationChecker} needs: bulk scope retrieval for search
 * pre-filtering, property-scoped bulk retrieval for the property-based authorization check, point
 * scope existence checks for get-by-id operations, and permission discovery for resource detail
 * views.
 */
public interface AuthorizationScopeRepositoryPort {

  /**
   * Returns all {@link AuthorizationScope} records the given owners hold for the specified resource
   * type and permission. The result is used to populate pre-query filters so search backends can
   * restrict results to authorized resources.
   *
   * @param ownerIds a map of entity type to the set of IDs belonging to that entity type for the
   *     authenticated principal (user ID, client ID, group IDs, role IDs, mapping-rule IDs)
   * @param resourceType the type of resource being accessed
   * @param permissionType the permission being exercised
   * @return the matching authorization scopes, or an empty list if none exist
   */
  List<AuthorizationScope> findAuthorizedScopes(
      Map<EntityType, Set<String>> ownerIds,
      AuthorizationResourceType resourceType,
      PermissionType permissionType);

  /**
   * Returns the {@link AuthorizationScope} records with matcher {@link
   * AuthorizationResourceMatcher#PROPERTY} that the given owners hold for the specified resource
   * type and permission, restricted to {@code propertyNames}. Used by the property-based
   * authorization check, which trusts this contract and does not re-filter the result.
   *
   * <p><strong>Contract:</strong> every returned scope must have matcher {@code PROPERTY} and a
   * {@code resourcePropertyName} contained in {@code propertyNames}. The default implementation
   * delegates to {@link #findAuthorizedScopes} and filters in memory, so it changes no behavior for
   * hosts that don't override it. Hosts with a large scope volume per principal should override
   * this with a store-level filtered query to avoid the property check pulling every scope for the
   * (resourceType, permissionType) pair.
   *
   * @param ownerIds a map of entity type to the set of IDs belonging to that entity type for the
   *     authenticated principal (user ID, client ID, group IDs, role IDs, mapping-rule IDs)
   * @param resourceType the type of resource being accessed
   * @param permissionType the permission being exercised
   * @param propertyNames the declared resource property names to restrict the result to
   * @return the matching PROPERTY-scoped authorization scopes, or an empty list if none exist
   */
  default List<AuthorizationScope> findAuthorizedPropertyScopes(
      final Map<EntityType, Set<String>> ownerIds,
      final AuthorizationResourceType resourceType,
      final PermissionType permissionType,
      final Set<String> propertyNames) {
    return findAuthorizedScopes(ownerIds, resourceType, permissionType).stream()
        .filter(scope -> scope.getMatcher() == AuthorizationResourceMatcher.PROPERTY)
        .filter(scope -> propertyNames.contains(scope.getResourcePropertyName()))
        .toList();
  }

  /**
   * Returns {@code true} if any authorization record exists that grants the given owners access to
   * one of {@code resourceIds} for the given resource type and permission.
   *
   * <p>Callers typically pass {@code List.of(AuthorizationScope.WILDCARD.getResourceId(),
   * specificId)} so both wildcard and specific-ID grants are covered in a single query.
   *
   * @param ownerIds a map of entity type to owner IDs for the authenticated principal
   * @param resourceType the type of resource being accessed
   * @param permissionType the permission being exercised
   * @param resourceIds the resource IDs to check (usually wildcard + specific ID)
   * @return {@code true} if at least one matching authorization record exists
   */
  boolean hasAuthorizedScope(
      Map<EntityType, Set<String>> ownerIds,
      AuthorizationResourceType resourceType,
      PermissionType permissionType,
      List<String> resourceIds);

  /**
   * Returns the union of all {@link PermissionType} values the given owners hold on the resources
   * identified by {@code resourceIds}.
   *
   * <p>Callers typically pass {@code List.of(AuthorizationScope.WILDCARD.getResourceId(),
   * specificId)} so permissions from wildcard grants are included in the result.
   *
   * @param ownerIds a map of entity type to owner IDs for the authenticated principal
   * @param resourceType the type of resource being accessed
   * @param resourceIds the resource IDs to collect permissions for (usually wildcard + specific ID)
   * @return the set of permissions held; empty if no matching records exist
   */
  Set<PermissionType> findPermissionTypes(
      Map<EntityType, Set<String>> ownerIds,
      AuthorizationResourceType resourceType,
      List<String> resourceIds);
}
