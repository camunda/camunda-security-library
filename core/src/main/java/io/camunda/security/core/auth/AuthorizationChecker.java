/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class AuthorizationChecker {

  private static final Logger LOG = LoggerFactory.getLogger(AuthorizationChecker.class);

  private final AuthorizationScopeRepositoryPort scopeRepository;

  public AuthorizationChecker(final AuthorizationScopeRepositoryPort scopeRepository) {
    this.scopeRepository = scopeRepository;
  }

  public List<AuthorizationScope> retrieveAuthorizedAuthorizationScopes(
      final CamundaAuthentication authentication, final RequiredAuthorization<?> authorization) {
    return getOrElseDefaultResult(
        authentication,
        ownerIds -> {
          final var scopes =
              scopeRepository.findAuthorizedScopes(
                  ownerIds, authorization.resourceType(), authorization.permissionType());
          LOG.debug(
              "Retrieved {} authorization scope(s) for resource type [{}], permission [{}]",
              scopes.size(),
              authorization.resourceType(),
              authorization.permissionType());
          return scopes;
        },
        List::of);
  }

  public boolean isAuthorized(
      final AuthorizationScope authorizationScope,
      final CamundaAuthentication authentication,
      final RequiredAuthorization<?> authorization) {
    return getOrElseDefaultResult(
        authentication,
        ownerIds ->
            scopeRepository.hasAuthorizedScope(
                ownerIds,
                authorization.resourceType(),
                authorization.permissionType(),
                List.of(
                    AuthorizationScope.WILDCARD.getResourceId(),
                    authorizationScope.getResourceId())),
        () -> false);
  }

  public Set<PermissionType> collectPermissionTypes(
      final String resourceId,
      final AuthorizationResourceType resourceType,
      final CamundaAuthentication authentication) {
    return getOrElseDefaultResult(
        authentication,
        ownerIds ->
            scopeRepository.findPermissionTypes(
                ownerIds,
                resourceType,
                List.of(AuthorizationScope.WILDCARD.getResourceId(), resourceId)),
        Set::of);
  }

  private <T> T getOrElseDefaultResult(
      final CamundaAuthentication authentication,
      final Function<Map<EntityType, Set<String>>, T> resultSupplier,
      final Supplier<T> defaultResultSupplier) {
    final var ownerTypeToOwnerIds = collectOwnerTypeToOwnerIds(authentication);
    return Optional.of(ownerTypeToOwnerIds)
        .filter(m -> !m.isEmpty())
        .map(resultSupplier)
        .orElseGet(defaultResultSupplier);
  }

  private Map<EntityType, Set<String>> collectOwnerTypeToOwnerIds(
      final CamundaAuthentication authentication) {
    final var ownerTypeToOwnerIds = new HashMap<EntityType, Set<String>>();
    if (authentication.authenticatedUsername() != null) {
      ownerTypeToOwnerIds.put(EntityType.USER, Set.of(authentication.authenticatedUsername()));
    }
    if (authentication.authenticatedClientId() != null) {
      ownerTypeToOwnerIds.put(EntityType.CLIENT, Set.of(authentication.authenticatedClientId()));
    }
    final var groups = authentication.authenticatedGroupIds();
    if (groups != null && !groups.isEmpty()) {
      ownerTypeToOwnerIds.put(EntityType.GROUP, new HashSet<>(groups));
    }
    final var roles = authentication.authenticatedRoleIds();
    if (roles != null && !roles.isEmpty()) {
      ownerTypeToOwnerIds.put(EntityType.ROLE, new HashSet<>(roles));
    }
    final var mappingRules = authentication.authenticatedMappingRuleIds();
    if (mappingRules != null && !mappingRules.isEmpty()) {
      ownerTypeToOwnerIds.put(EntityType.MAPPING_RULE, new HashSet<>(mappingRules));
    }
    LOG.debug("Resolved authorization principals: {}", ownerTypeToOwnerIds);
    return ownerTypeToOwnerIds;
  }
}
