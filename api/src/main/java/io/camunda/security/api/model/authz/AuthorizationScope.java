/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

public class AuthorizationScope {

  public static final String WILDCARD_CHAR = "*";
  public static final AuthorizationScope WILDCARD =
      new AuthorizationScope(AuthorizationResourceMatcher.ANY, WILDCARD_CHAR);

  private @Nullable AuthorizationResourceMatcher matcher;
  private @Nullable String resourceId;
  private @Nullable String resourcePropertyName;

  public AuthorizationScope() {}

  public AuthorizationScope(
      final AuthorizationResourceMatcher matcher, final @Nullable String resourceId) {
    this(matcher, resourceId, "");
  }

  public AuthorizationScope(
      final AuthorizationResourceMatcher matcher,
      final @Nullable String resourceId,
      final @Nullable String resourcePropertyName) {
    this.matcher = matcher;

    // Since this class is used for comparisons, normalize null to empty string for these fields
    // to handle cases where null is provided while empty string is expected. resourceId may be
    // null for PROPERTY-matcher authorizations (see #40079); resourcePropertyName was introduced
    // in 8.9.0 with the same normalization convention.
    this.resourceId = resourceId != null ? resourceId : "";
    this.resourcePropertyName = resourcePropertyName != null ? resourcePropertyName : "";
  }

  public @Nullable AuthorizationResourceMatcher getMatcher() {
    return matcher;
  }

  public AuthorizationScope setMatcher(final @Nullable AuthorizationResourceMatcher matcher) {
    this.matcher = matcher;
    return this;
  }

  public @Nullable String getResourceId() {
    return resourceId;
  }

  public AuthorizationScope setResourceId(final @Nullable String resourceId) {
    this.resourceId = resourceId;
    return this;
  }

  public @Nullable String getResourcePropertyName() {
    return resourcePropertyName;
  }

  public AuthorizationScope setResourcePropertyName(final @Nullable String resourcePropertyName) {
    this.resourcePropertyName = resourcePropertyName;
    return this;
  }

  @Override
  public int hashCode() {
    return Objects.hash(matcher, resourceId, resourcePropertyName);
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj instanceof AuthorizationScope) {
      final AuthorizationScope other = (AuthorizationScope) obj;
      return Objects.equals(matcher, other.matcher)
          && Objects.equals(resourceId, other.resourceId)
          && Objects.equals(resourcePropertyName, other.resourcePropertyName);
    }
    return false;
  }

  @Override
  public String toString() {
    return "AuthorizationScope{"
        + "matcher="
        + matcher
        + ", resourceId='"
        + resourceId
        + '\''
        + ", resourcePropertyName='"
        + resourcePropertyName
        + '\''
        + '}';
  }

  public static AuthorizationScope id(final @Nullable String resourceId)
      throws IllegalArgumentException {
    if (WILDCARD_CHAR.equals(resourceId)) {
      final String errorMsg =
          String.format(
              "Resource ID cannot be the wildcard character '%s'. For declaring WILDCARD access, please use the AuthorizationScope.WILDCARD constant.",
              WILDCARD_CHAR);
      throw new IllegalArgumentException(errorMsg);
    }
    return new AuthorizationScope(AuthorizationResourceMatcher.ID, resourceId);
  }

  public static AuthorizationScope property(final @Nullable String resourcePropertyName)
      throws IllegalArgumentException {
    if (resourcePropertyName == null || resourcePropertyName.isEmpty()) {
      throw new IllegalArgumentException("Resource property name cannot be null or empty");
    }
    return new AuthorizationScope(AuthorizationResourceMatcher.PROPERTY, "", resourcePropertyName);
  }

  public static AuthorizationScope of(final @Nullable String resourceId) {
    if (WILDCARD_CHAR.equals(resourceId)) {
      return WILDCARD;
    }

    return id(resourceId);
  }
}
