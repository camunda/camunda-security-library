/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
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

/**
 * Evaluates authorization queries against the host's authorization store via {@link
 * AuthorizationScopeRepositoryPort}.
 *
 * <p>Resolves the principal identity from a {@link CamundaAuthentication} into a map of {@link
 * io.camunda.security.api.model.authz.EntityType}-to-IDs and delegates to the port. Returns empty
 * results (rather than throwing) when the authentication carries no identifiable principal — this
 * covers anonymous and unset authentication contexts.
 *
 * <p>The three public methods correspond to the three query patterns used by OC:
 *
 * <ul>
 *   <li>{@link #retrieveAuthorizedAuthorizationScopes} — bulk scope fetch for search pre-filtering
 *   <li>{@link #isAuthorized} — point check for get-by-id operations
 *   <li>{@link #collectPermissionTypes} — permission discovery for resource detail views
 * </ul>
 *
 * <p>Wired as a Spring bean by {@code AuthorizationCheckerConfiguration} (in {@code
 * io.camunda.security.spring.authz}) when the host provides an {@link
 * AuthorizationScopeRepositoryPort} bean. The {@code @link} is intentionally omitted — {@code core}
 * has no compile dependency on {@code spring-boot-starter}.
 */
public final class AuthorizationChecker {

  private static final Logger LOG = LoggerFactory.getLogger(AuthorizationChecker.class);

  private final AuthorizationScopeRepositoryPort scopeRepository;

  /**
   * Creates a new checker backed by the given port.
   *
   * @param scopeRepository the host-supplied authorization store adapter
   */
  public AuthorizationChecker(final AuthorizationScopeRepositoryPort scopeRepository) {
    this.scopeRepository = java.util.Objects.requireNonNull(scopeRepository, "scopeRepository");
  }

  /**
   * Returns all {@link AuthorizationScope} records the principal holds for the resource type and
   * permission declared in {@code authorization}. Used to populate pre-query filters in search
   * backends.
   *
   * <p>Returns an empty list when the authentication carries no identifiable principal (anonymous
   * or unset).
   *
   * @param authentication the resolved authentication context of the caller
   * @param authorization the authorization requirement specifying the resource type and permission
   */
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

  /**
   * Returns {@code true} if the principal holds an authorization record that covers {@code
   * authorizationScope} for the resource type and permission declared in {@code authorization}.
   * Always checks both the wildcard scope and the specific scope so wildcard grants are honoured.
   *
   * <p>Returns {@code false} when the authentication carries no identifiable principal.
   *
   * @param authorizationScope the specific scope (resource ID) being accessed
   * @param authentication the resolved authentication context of the caller
   * @param authorization the authorization requirement specifying the resource type and permission
   */
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

  /**
   * Returns all {@link PermissionType} values the principal holds on {@code resourceId} for {@code
   * resourceType}. Checks both the wildcard resource and the specific ID so wildcard grants
   * contribute to the result set.
   *
   * <p>Returns an empty set when the authentication carries no identifiable principal.
   *
   * @param resourceId the specific resource ID to collect permissions for
   * @param resourceType the type of the resource
   * @param authentication the resolved authentication context of the caller
   */
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
    LOG.debug("Resolved authorization owner types: {}", ownerTypeToOwnerIds.keySet());
    return ownerTypeToOwnerIds;
  }
}
