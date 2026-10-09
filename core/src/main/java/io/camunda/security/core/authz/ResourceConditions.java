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
import io.camunda.security.api.model.authz.Condition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.PrincipalAttribute;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The semantics of {@link Condition}s, shared by the single check and the list filter so that both
 * evaluate the same rule: a condition is met when the values of the resource attribute overlap with
 * the values of the operand, and a resource that does not provide the attribute does not meet it.
 */
final class ResourceConditions {

  private ResourceConditions() {}

  /** Resolves {@code operand} to concrete values. Principal values that are absent are empty. */
  static Set<String> resolve(final Operand operand, final CamundaAuthentication authentication) {
    return switch (operand) {
      case final Operand.Values values -> nonEmpty(values.values());
      case final Operand.Principal principal ->
          principalValues(principal.attribute(), authentication);
    };
  }

  static Condition resolved(final Condition condition, final CamundaAuthentication authentication) {
    return new Condition(
        condition.attribute(), new Operand.Values(resolve(condition.operand(), authentication)));
  }

  static boolean isMet(
      final Condition condition,
      final Map<ResourceAttribute, Set<String>> attributes,
      final CamundaAuthentication authentication) {
    final var resourceValues = attributes.get(condition.attribute());
    return resourceValues != null
        && !Collections.disjoint(resourceValues, resolve(condition.operand(), authentication));
  }

  static boolean allMet(
      final List<Condition> conditions,
      final Map<ResourceAttribute, Set<String>> attributes,
      final CamundaAuthentication authentication) {
    return conditions.stream().allMatch(condition -> isMet(condition, attributes, authentication));
  }

  /**
   * Translates a stored property grant of OC's user task authorization into the principal condition
   * it stands for. Returns empty for a property that {@code resourceType} has no attribute for.
   */
  static Optional<Condition> propertyCondition(
      final AuthorizationResourceType resourceType, final String propertyName) {
    final Optional<Condition> condition =
        switch (propertyName) {
          case RequiredAuthorization.PROP_ASSIGNEE ->
              Optional.of(
                  principalCondition(ResourceAttribute.ASSIGNEE, PrincipalAttribute.USERNAME));
          case RequiredAuthorization.PROP_CANDIDATE_USERS ->
              Optional.of(
                  principalCondition(
                      ResourceAttribute.CANDIDATE_USERS, PrincipalAttribute.USERNAME));
          case RequiredAuthorization.PROP_CANDIDATE_GROUPS ->
              Optional.of(
                  principalCondition(
                      ResourceAttribute.CANDIDATE_GROUPS, PrincipalAttribute.GROUP_IDS));
          default -> Optional.empty();
        };
    return condition.filter(c -> resourceType.getSupportedAttributes().contains(c.attribute()));
  }

  /**
   * Whether {@code authorization} asks for property grants only, so that grants on resource IDs do
   * not take part. This is the case when it names properties and neither supplies nor carries
   * resource IDs.
   */
  static boolean isPropertyOnly(final RequiredAuthorization<?> authorization) {
    return authorization.hasAnyResourcePropertyNames()
        && authorization.resourceIdSupplier() == null
        && !authorization.hasAnyResourceIds();
  }

  private static Condition principalCondition(
      final ResourceAttribute attribute, final PrincipalAttribute principalAttribute) {
    return new Condition(attribute, new Operand.Principal(principalAttribute));
  }

  private static Set<String> principalValues(
      final PrincipalAttribute attribute, final CamundaAuthentication authentication) {
    return switch (attribute) {
      case USERNAME -> nonEmpty(authentication.authenticatedUsername());
      case CLIENT_ID -> nonEmpty(authentication.authenticatedClientId());
      case GROUP_IDS -> nonEmpty(authentication.authenticatedGroupIds());
      case TENANT_IDS -> nonEmpty(authentication.authenticatedTenantIds());
    };
  }

  private static Set<String> nonEmpty(final String value) {
    return value == null || value.isEmpty() ? Set.of() : Set.of(value);
  }

  private static Set<String> nonEmpty(final Collection<String> values) {
    return values.stream()
        .filter(value -> value != null && !value.isEmpty())
        .collect(Collectors.toUnmodifiableSet());
  }
}
