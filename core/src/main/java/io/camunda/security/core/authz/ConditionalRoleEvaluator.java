/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.api.model.authz.RoleMembership;
import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Evaluates a check on a resource object whose type has a {@code ResourceAttributeExtractor}. The
 * principal's roles are its unconditional roles plus the roles of the {@link RoleMembership}s whose
 * conditions the resource meets. Grants on resource IDs and property grants are looked up for those
 * roles; a property grant stands for the principal condition that {@link ResourceConditions} maps
 * it to.
 */
final class ConditionalRoleEvaluator {

  private final AuthorizationChecker authorizationChecker;
  private final ResourceAttributeExtractorRegistry attributeExtractorRegistry;

  ConditionalRoleEvaluator(
      final AuthorizationChecker authorizationChecker,
      final ResourceAttributeExtractorRegistry attributeExtractorRegistry) {
    this.authorizationChecker = authorizationChecker;
    this.attributeExtractorRegistry = attributeExtractorRegistry;
  }

  <T> Decision evaluate(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> authorization,
      final T resource) {
    final var attributes =
        attributeExtractorRegistry.attributesOf(authorization.resourceType(), resource);
    final Set<String> conditionalRoleIds = applicableRoleIds(authentication, attributes);

    String resourceId = null;
    if (!ResourceConditions.isPropertyOnly(authorization)) {
      resourceId = ResourceIdResolver.resolveResourceId(authorization, resource);
      if (authorizationChecker.isAuthorized(
          AuthorizationScope.of(resourceId),
          authentication,
          authorization.withResourceId(resourceId),
          conditionalRoleIds)) {
        return new Decision(true, resourceId);
      }
    }

    final boolean grantedByProperty =
        authorization.hasAnyResourcePropertyNames()
            && isGrantedByProperty(authentication, authorization, attributes, conditionalRoleIds);
    return new Decision(grantedByProperty, resourceId);
  }

  /** The IDs of the roles of the principal whose membership conditions the resource meets. */
  Set<String> applicableRoleIds(
      final CamundaAuthentication authentication,
      final Map<ResourceAttribute, Set<String>> attributes) {
    return authentication.roleMemberships().stream()
        .filter(
            membership ->
                ResourceConditions.allMet(membership.conditions(), attributes, authentication))
        .map(RoleMembership::roleId)
        .collect(Collectors.toUnmodifiableSet());
  }

  private boolean isGrantedByProperty(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<?> authorization,
      final Map<ResourceAttribute, Set<String>> attributes,
      final Set<String> conditionalRoleIds) {
    return authorizationChecker
        .retrieveAuthorizedPropertyScopes(
            authentication,
            authorization,
            authorization.resourcePropertyNames(),
            conditionalRoleIds)
        .stream()
        .map(
            scope ->
                ResourceConditions.propertyCondition(
                    authorization.resourceType(), scope.getResourcePropertyName()))
        .flatMap(Optional::stream)
        .anyMatch(condition -> ResourceConditions.isMet(condition, attributes, authentication));
  }

  /**
   * The outcome of an evaluation.
   *
   * @param allowed whether access is granted
   * @param resourceId the resource ID the check was evaluated under, or {@code null} for a check
   *     that asks for property grants only
   */
  record Decision(boolean allowed, String resourceId) {}
}
