/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.ConditionalMembership;
import io.camunda.security.api.model.authz.MembershipCondition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.ResourceAttribute;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Finds the conditional role memberships of a principal that apply to a resource (ADR-0041). A
 * membership applies when the attributes of the resource meet all of its conditions.
 *
 * <p>Anything that cannot be evaluated does not apply (ADR-0041 D4): no extractor for the resource,
 * an extractor that throws, and an attribute without a value. {@link Operand.Equals} compares the
 * values literally, so {@code *} matches only {@code *}.
 */
final class ConditionalRoleEvaluator {

  private static final Logger LOG = LoggerFactory.getLogger(ConditionalRoleEvaluator.class);

  private final ResourceAttributeExtractorRegistry extractorRegistry;
  // An extractor that fails usually fails on every check, so log a WARN once per extractor class
  // and DEBUG after that.
  private final Set<Class<?>> reportedFailingExtractors = ConcurrentHashMap.newKeySet();

  ConditionalRoleEvaluator(final ResourceAttributeExtractorRegistry extractorRegistry) {
    this.extractorRegistry = Objects.requireNonNull(extractorRegistry, "extractorRegistry");
  }

  /**
   * Returns the IDs of the roles of the conditional memberships of {@code authentication} whose
   * conditions {@code resource} meets.
   */
  <T> Set<String> applicableRoleIds(
      final CamundaAuthentication authentication,
      final AuthorizationResourceType resourceType,
      final T resource) {
    final List<ConditionalMembership> memberships = authentication.conditionalRoleMemberships();
    if (memberships.isEmpty()) {
      return Set.of();
    }
    final var attributes = attributesOf(resourceType, resource);
    if (attributes.isEmpty()) {
      return Set.of();
    }
    return memberships.stream()
        .filter(membership -> allMet(membership.conditions(), attributes))
        .map(ConditionalMembership::id)
        .collect(Collectors.toUnmodifiableSet());
  }

  private <T> Map<ResourceAttribute, Set<String>> attributesOf(
      final AuthorizationResourceType resourceType, final T resource) {
    final Optional<ResourceAttributeExtractor<T>> extractor =
        extractorRegistry.findMatching(resourceType, resource);
    if (extractor.isEmpty()) {
      LOG.debug(
          "No ResourceAttributeExtractor for resource type [{}] accepts a resource of class [{}];"
              + " conditional role memberships do not apply",
          resourceType,
          resource.getClass().getName());
      return Map.of();
    }
    try {
      final var attributes = extractor.get().attributesOf(resource);
      return attributes == null ? Map.of() : attributes;
    } catch (final RuntimeException e) {
      reportExtractorFailure(resourceType, extractor.get(), e);
      return Map.of();
    }
  }

  private void reportExtractorFailure(
      final AuthorizationResourceType resourceType,
      final ResourceAttributeExtractor<?> extractor,
      final RuntimeException e) {
    final var extractorClass = extractor.getClass();
    if (reportedFailingExtractors.add(extractorClass)) {
      LOG.warn(
          "ResourceAttributeExtractor [{}] for resource type [{}] threw while reading resource"
              + " attributes; conditional role memberships do not apply. Later failures of this"
              + " extractor are logged at DEBUG.",
          extractorClass.getName(),
          resourceType,
          e);
    } else {
      LOG.debug(
          "ResourceAttributeExtractor [{}] for resource type [{}] threw while reading resource"
              + " attributes; conditional role memberships do not apply",
          extractorClass.getName(),
          resourceType,
          e);
    }
  }

  private static boolean allMet(
      final List<MembershipCondition> conditions,
      final Map<ResourceAttribute, Set<String>> attributes) {
    return conditions.stream().allMatch(condition -> isMet(condition, attributes));
  }

  private static boolean isMet(
      final MembershipCondition condition, final Map<ResourceAttribute, Set<String>> attributes) {
    final Set<String> values = attributes.get(condition.attribute());
    if (values == null || values.isEmpty()) {
      return false;
    }
    return switch (condition.operand()) {
      case Operand.Equals equals -> values.contains(equals.value());
    };
  }
}
