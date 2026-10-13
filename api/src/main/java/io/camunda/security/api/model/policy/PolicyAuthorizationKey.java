/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static io.camunda.security.api.model.policy.PolicyValidation.nullToEmpty;
import static io.camunda.security.api.model.policy.PolicyValidation.requireId;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.AuthorizationResourceMatcher;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import java.util.Objects;

/**
 * Identity of an authorization: owner, resource type and scope. Null {@code resourceId} and {@code
 * resourcePropertyName} are normalised to the empty string. Validated per matcher like {@link
 * AuthorizationScope}: {@code ID} needs a non-wildcard resource ID, {@code ANY} needs the wildcard
 * {@code "*"}, {@code PROPERTY} needs a property name and no resource ID.
 */
public record PolicyAuthorizationKey(
    AuthorizationOwnerType ownerType,
    String ownerId,
    AuthorizationResourceType resourceType,
    AuthorizationResourceMatcher matcher,
    String resourceId,
    String resourcePropertyName) {

  public PolicyAuthorizationKey {
    Objects.requireNonNull(ownerType, "ownerType must not be null");
    Objects.requireNonNull(resourceType, "resourceType must not be null");
    Objects.requireNonNull(matcher, "matcher must not be null");
    if (ownerType == AuthorizationOwnerType.UNSPECIFIED) {
      throw new IllegalArgumentException("ownerType must not be UNSPECIFIED");
    }
    if (resourceType == AuthorizationResourceType.UNSPECIFIED) {
      throw new IllegalArgumentException("resourceType must not be UNSPECIFIED");
    }
    requireId(ownerId, "ownerId");
    resourceId = nullToEmpty(resourceId);
    resourcePropertyName = nullToEmpty(resourcePropertyName);
    validateScope(matcher, resourceId, resourcePropertyName);
  }

  private static void validateScope(
      final AuthorizationResourceMatcher matcher,
      final String resourceId,
      final String propertyName) {
    switch (matcher) {
      case ID -> {
        if (resourceId.isBlank() || AuthorizationScope.WILDCARD_CHAR.equals(resourceId)) {
          throw new IllegalArgumentException(
              "ID matcher requires a non-blank, non-wildcard resourceId");
        }
        requireEmptyPropertyName(matcher, propertyName);
      }
      case ANY -> {
        if (!AuthorizationScope.WILDCARD_CHAR.equals(resourceId)) {
          throw new IllegalArgumentException("ANY matcher requires resourceId '*'");
        }
        requireEmptyPropertyName(matcher, propertyName);
      }
      case PROPERTY -> {
        if (propertyName.isBlank()) {
          throw new IllegalArgumentException("PROPERTY matcher requires a resourcePropertyName");
        }
        if (!resourceId.isEmpty()) {
          throw new IllegalArgumentException("PROPERTY matcher requires an empty resourceId");
        }
      }
      default -> throw new IllegalArgumentException("matcher must not be " + matcher);
    }
  }

  private static void requireEmptyPropertyName(
      final AuthorizationResourceMatcher matcher, final String propertyName) {
    if (!propertyName.isEmpty()) {
      throw new IllegalArgumentException(
          matcher + " matcher requires an empty resourcePropertyName");
    }
  }
}
