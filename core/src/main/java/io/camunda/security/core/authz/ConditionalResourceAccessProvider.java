/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceMatcher;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.ConditionalMembership;
import io.camunda.security.api.model.authz.MembershipCondition;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.ResourceAccessFilter.Term;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link ResourceAccessProvider} that counts the conditional role memberships of the principal
 * (ADR-0041), by the same rule as the single check of {@link AuthorizationService}. A list filtered
 * by {@link #resolveResourceAccess} therefore contains exactly the resources that the single check
 * allows, provided that each resource has an ID and the host stores the attributes that its
 * extractor reads. The single check denies a resource without an ID, and a resource whose extractor
 * throws gets no conditional role.
 *
 * <p>{@link #resolveResourceAccess} returns a {@link ResourceAccess} whose {@link
 * ResourceAccess#filter() filter} has these terms:
 *
 * <ul>
 *   <li>a grant on every resource, held directly or through a global role: every resource ({@link
 *       ResourceAccessFilter.All});
 *   <li>grants on resource IDs, held the same way: those IDs;
 *   <li>a grant of the role of a conditional membership: the same, limited by the conditions of the
 *       membership.
 * </ul>
 *
 * <p>Conditional memberships count only for a resource type with a {@link
 * io.camunda.security.api.context.ResourceAttributeExtractor}, as in the single check. Reading the
 * grants of the conditional roles takes one query per distinct role.
 *
 * <p>Property grants are not supported: a requirement with resource property names is rejected with
 * an {@link IllegalArgumentException}, so that a filter never leaves out what a property grant
 * allows.
 */
public final class ConditionalResourceAccessProvider implements ResourceAccessProvider {

  private static final Logger LOG =
      LoggerFactory.getLogger(ConditionalResourceAccessProvider.class);

  private final AuthorizationChecker authorizationChecker;
  private final ResourceAttributeExtractorRegistry extractorRegistry;
  private final ConditionalRoleEvaluator conditionalRoleEvaluator;

  public ConditionalResourceAccessProvider(
      final AuthorizationChecker authorizationChecker,
      final ResourceAttributeExtractorRegistry extractorRegistry) {
    this.authorizationChecker =
        Objects.requireNonNull(authorizationChecker, "authorizationChecker");
    this.extractorRegistry = Objects.requireNonNull(extractorRegistry, "extractorRegistry");
    conditionalRoleEvaluator = new ConditionalRoleEvaluator(extractorRegistry);
  }

  /**
   * Resolves the resources that the principal may access, as a {@link ResourceAccessFilter} that
   * the host translates into its query.
   *
   * @throws IllegalArgumentException if {@code authorization} has resource property names
   */
  @Override
  public <T> ResourceAccess resolveResourceAccess(
      final CamundaAuthentication authentication, final RequiredAuthorization<T> authorization) {
    rejectPropertyNames(authorization);
    final var globalScopes =
        authorizationChecker.retrieveAuthorizedAuthorizationScopes(authentication, authorization);
    final List<Term> terms = new ArrayList<>(termsOf(globalScopes, List.of()));

    if (extractorRegistry.hasExtractorsFor(authorization.resourceType())) {
      final Map<String, List<AuthorizationScope>> scopesByRole = new HashMap<>();
      for (final ConditionalMembership membership : authentication.conditionalRoleMemberships()) {
        final var scopes =
            scopesByRole.computeIfAbsent(
                membership.id(),
                roleId ->
                    authorizationChecker.retrieveAuthorizedAuthorizationScopesOfRole(
                        roleId, authorization));
        terms.addAll(termsOf(scopes, membership.conditions()));
      }
    }

    final ResourceAccessFilter filter = ResourceAccessFilter.anyOf(terms);
    LOG.debug(
        "Resolved {} for resource type [{}], permission [{}] with {} term(s)",
        filter.getClass().getSimpleName(),
        authorization.resourceType(),
        authorization.permissionType(),
        terms.size());
    return switch (filter) {
      case ResourceAccessFilter.All all ->
          ResourceAccess.wildcard(
              authorization.withResourceId(AuthorizationScope.WILDCARD.getResourceId()));
      case ResourceAccessFilter.None none -> ResourceAccess.denied(authorization);
      case ResourceAccessFilter.AnyOf anyOf ->
          ResourceAccess.of(withGrantedResourceIds(authorization, globalScopes), anyOf);
    };
  }

  /**
   * Checks one resource with the same rule as the single check: the grants of the global roles, and
   * of the conditional roles whose conditions {@code resource} meets, on the ID of {@code
   * resource}. The ID comes from the {@code resourceIdSupplier} of {@code requiredAuthorization},
   * or from its only resource ID. A resource without an ID is denied.
   *
   * @throws IllegalArgumentException if {@code requiredAuthorization} has resource property names,
   *     or neither a {@code resourceIdSupplier} nor exactly one resource ID
   */
  @Override
  public <T> ResourceAccess hasResourceAccess(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> requiredAuthorization,
      final T resource) {
    rejectPropertyNames(requiredAuthorization);
    final String resourceId = resourceIdOf(requiredAuthorization, resource);
    if (resourceId == null) {
      return ResourceAccess.denied(requiredAuthorization);
    }
    final Set<String> conditionalRoleIds =
        extractorRegistry.hasExtractorsFor(requiredAuthorization.resourceType())
            ? conditionalRoleEvaluator.applicableRoleIds(
                authentication, requiredAuthorization.resourceType(), resource)
            : Set.of();
    return byResourceId(authentication, requiredAuthorization, resourceId, conditionalRoleIds);
  }

  /**
   * Checks the resource with ID {@code resourceId} with the grants of the global roles only.
   * Conditional memberships do not count, because their conditions need the resource's attributes:
   * use {@link #hasResourceAccess} with the resource for them.
   *
   * @throws IllegalArgumentException if {@code requiredAuthorization} has resource property names
   */
  @Override
  public <T> ResourceAccess hasResourceAccessByResourceId(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> requiredAuthorization,
      final String resourceId) {
    rejectPropertyNames(requiredAuthorization);
    return byResourceId(authentication, requiredAuthorization, resourceId, Set.of());
  }

  private <T> ResourceAccess byResourceId(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> requiredAuthorization,
      final String resourceId,
      final Set<String> conditionalRoleIds) {
    final var checked = requiredAuthorization.withResourceIds(List.of(resourceId));
    return authorizationChecker.isAuthorized(
            AuthorizationScope.of(resourceId),
            authentication,
            requiredAuthorization,
            conditionalRoleIds)
        ? ResourceAccess.allowed(checked)
        : ResourceAccess.denied(checked);
  }

  /**
   * Returns the terms for the grants in {@code scopes}, limited by {@code conditions}: one that
   * matches every resource for a grant on all of them, and one with the granted IDs for grants on
   * IDs.
   */
  private static List<Term> termsOf(
      final List<AuthorizationScope> scopes, final List<MembershipCondition> conditions) {
    final List<Term> terms = new ArrayList<>();
    if (scopes.stream().anyMatch(s -> s.getMatcher() == AuthorizationResourceMatcher.ANY)) {
      terms.add(new Term(Set.of(), conditions));
    }
    final Set<String> resourceIds = resourceIdsOf(scopes);
    if (!resourceIds.isEmpty()) {
      terms.add(new Term(resourceIds, conditions));
    }
    return terms;
  }

  /**
   * Returns {@code authorization} with the IDs that {@code scopes} grant, so that a consumer that
   * reads only {@link ResourceAccess#authorization()} sees the resources granted without
   * conditions. Returns {@code authorization} unchanged if they grant no ID.
   */
  private static <T> RequiredAuthorization<T> withGrantedResourceIds(
      final RequiredAuthorization<T> authorization, final List<AuthorizationScope> scopes) {
    final Set<String> resourceIds = resourceIdsOf(scopes);
    return resourceIds.isEmpty()
        ? authorization
        : authorization.withResourceIds(List.copyOf(resourceIds));
  }

  private static Set<String> resourceIdsOf(final List<AuthorizationScope> scopes) {
    final Set<String> resourceIds = new LinkedHashSet<>();
    for (final AuthorizationScope scope : scopes) {
      if (scope.getMatcher() == AuthorizationResourceMatcher.ID) {
        resourceIds.add(scope.getResourceId());
      }
    }
    return resourceIds;
  }

  private static <T> String resourceIdOf(
      final RequiredAuthorization<T> authorization, final T resource) {
    if (authorization.resourceIdSupplier() != null) {
      return authorization.resourceIdSupplier().apply(resource);
    }
    if (authorization.hasAnyResourceIds() && authorization.resourceIds().size() == 1) {
      return authorization.resourceIds().getFirst();
    }
    throw new IllegalArgumentException(
        ("A check on resource type %s needs a resourceIdSupplier or exactly one resource ID")
            .formatted(authorization.resourceType()));
  }

  private static void rejectPropertyNames(final RequiredAuthorization<?> authorization) {
    if (authorization.hasAnyResourcePropertyNames()) {
      throw new IllegalArgumentException(
          ("ConditionalResourceAccessProvider does not support resource property names, but the"
                  + " check on resource type %s has %s")
              .formatted(authorization.resourceType(), authorization.resourcePropertyNames()));
    }
  }
}
