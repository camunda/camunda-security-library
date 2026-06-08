/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.reader;

import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.auth.condition.AuthorizationCondition;
import io.camunda.security.core.auth.condition.AuthorizationConditions;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Describes whether resource-level authorization should be enforced for a query or operation, and
 * if so, which {@link AuthorizationCondition} governs the check.
 *
 * <p>When {@link #enabled()} is {@code false} the check is entirely bypassed — the caller may
 * access any resource. When enabled, the {@link #authorizationCondition()} carries the set of
 * {@link RequiredAuthorization} specs that the principal must satisfy.
 *
 * <p>Used by {@link ResourceAccessChecks} and search backends to scope query results to resources
 * the authenticated principal is allowed to see.
 */
public record AuthorizationCheck(boolean enabled, AuthorizationCondition authorizationCondition) {

  /**
   * Creates an enabled check wrapping a single {@link RequiredAuthorization} as a {@link
   * io.camunda.security.core.auth.condition.SingleAuthorizationCondition}.
   */
  public static AuthorizationCheck enabled(final RequiredAuthorization<?> authorization) {
    return enabled(AuthorizationConditions.single(authorization));
  }

  /**
   * Creates an enabled check backed by the supplied {@link AuthorizationCondition}. {@code
   * authorizationCondition} may be {@code null}, in which case {@link #hasAnyResourceAccess()}
   * returns {@code false}.
   */
  public static AuthorizationCheck enabled(final AuthorizationCondition authorizationCondition) {
    return new AuthorizationCheck(true, authorizationCondition);
  }

  /**
   * Creates a disabled check — authorization is not enforced and all resource access is permitted.
   */
  public static AuthorizationCheck disabled() {
    return new AuthorizationCheck(false, null);
  }

  /**
   * Returns the flat list of {@link RequiredAuthorization} specs from the underlying condition, or
   * an empty list when the condition is {@code null}.
   */
  public List<RequiredAuthorization<?>> authorizations() {
    return Optional.ofNullable(authorizationCondition)
        .map(AuthorizationCondition::authorizations)
        .orElse(Collections.emptyList());
  }

  /**
   * Returns {@code true} when the caller has access to at least one resource. This is the case when
   * the check is disabled (authorization not enforced) or when at least one underlying
   * authorization carries resource IDs or resource property names that a search backend can use to
   * scope the query. Returns {@code false} when authorization is enabled but no scoping information
   * is present.
   */
  public boolean hasAnyResourceAccess() {
    return !enabled || hasAnyResourceIdAccess() || hasAnyResourcePropertyAccess();
  }

  private boolean hasAnyResourceIdAccess() {
    return anyAuthorizationMatches(RequiredAuthorization::hasAnyResourceIds);
  }

  private boolean hasAnyResourcePropertyAccess() {
    return anyAuthorizationMatches(RequiredAuthorization::hasAnyResourcePropertyNames);
  }

  private boolean anyAuthorizationMatches(final Predicate<RequiredAuthorization<?>> predicate) {
    if (authorizationCondition == null) {
      return false;
    }
    final var auths = authorizationCondition.authorizations();
    if (auths == null || auths.isEmpty()) {
      return false;
    }
    return auths.stream().anyMatch(predicate);
  }
}
