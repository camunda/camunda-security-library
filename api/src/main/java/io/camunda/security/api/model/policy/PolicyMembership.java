/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static io.camunda.security.api.model.policy.PolicyValidation.requireId;

import io.camunda.security.api.model.authz.EntityType;
import java.util.Objects;
import java.util.Set;

/**
 * A membership of {@code memberId} in the entity {@code targetId}. All four components together are
 * the identity. Only the canonical direction is allowed: roles accept users, clients, mapping rules
 * and groups; groups accept users, clients and mapping rules; tenants accept users, clients,
 * mapping rules, groups and roles. Users and clients are not entities, they only appear as members.
 */
public record PolicyMembership(
    PolicyMembershipTarget targetType, String targetId, EntityType memberType, String memberId) {

  private static final Set<EntityType> ROLE_MEMBERS =
      Set.of(EntityType.USER, EntityType.CLIENT, EntityType.MAPPING_RULE, EntityType.GROUP);
  private static final Set<EntityType> GROUP_MEMBERS =
      Set.of(EntityType.USER, EntityType.CLIENT, EntityType.MAPPING_RULE);
  private static final Set<EntityType> TENANT_MEMBERS =
      Set.of(
          EntityType.USER,
          EntityType.CLIENT,
          EntityType.MAPPING_RULE,
          EntityType.GROUP,
          EntityType.ROLE);

  public PolicyMembership {
    Objects.requireNonNull(targetType, "targetType must not be null");
    Objects.requireNonNull(memberType, "memberType must not be null");
    requireId(targetId, "targetId");
    requireId(memberId, "memberId");
    if (!allowedMembers(targetType).contains(memberType)) {
      throw new IllegalArgumentException(
          "Membership of a " + memberType + " in a " + targetType + " is not allowed");
    }
  }

  private static Set<EntityType> allowedMembers(final PolicyMembershipTarget target) {
    return switch (target) {
      case ROLE -> ROLE_MEMBERS;
      case GROUP -> GROUP_MEMBERS;
      case TENANT -> TENANT_MEMBERS;
    };
  }
}
