/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.authz.MembershipCondition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.ResourceAttribute;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The rule for {@link MembershipCondition}s, shared by the single check ({@link
 * ConditionalRoleEvaluator}) and the list filter ({@link ResourceAccessFilter}) so that both decide
 * the same way. A condition is met when the resource has a value for its attribute that the operand
 * accepts. A resource without a value for the attribute does not meet it (ADR-0041 D4).
 */
final class ResourceConditions {

  private ResourceConditions() {}

  /** Returns whether {@code attributes} meet every condition in {@code conditions}. */
  static boolean allMet(
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
