/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Outbound port for authorization scope queries. The host implements this backed by its
 * authorization data store. All methods receive pre-resolved owner-type-to-ids maps so the port
 * does not depend on {@link io.camunda.security.api.model.CamundaAuthentication}.
 */
public interface AuthorizationScopeRepositoryPort {

  /**
   * Returns all authorization scopes the given owners hold for {@code resourceType} / {@code
   * permissionType}.
   */
  List<AuthorizationScope> findAuthorizedScopes(
      Map<EntityType, Set<String>> ownerIds,
      AuthorizationResourceType resourceType,
      PermissionType permissionType);

  /**
   * Returns {@code true} if any authorization record exists for the given owners, resource type,
   * permission type, and one of {@code resourceIds} (typically wildcard + specific id).
   */
  boolean hasAuthorizedScope(
      Map<EntityType, Set<String>> ownerIds,
      AuthorizationResourceType resourceType,
      PermissionType permissionType,
      List<String> resourceIds);

  /**
   * Returns all permission types the given owners hold on the resources identified by {@code
   * resourceIds} (typically wildcard + specific id).
   */
  Set<PermissionType> findPermissionTypes(
      Map<EntityType, Set<String>> ownerIds,
      AuthorizationResourceType resourceType,
      List<String> resourceIds);
}
