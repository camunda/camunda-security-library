/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * The result of evaluating whether a principal has access to a specific resource.
 *
 * <p>Carries the verdict ({@link #allowed()}), whether it was granted via a wildcard scope ({@link
 * #wildcard()}), and the {@link RequiredAuthorization} that produced the result so callers can
 * trace which requirement was evaluated.
 *
 * <p>Provider implementations that resolve conditions also carry a {@link ResourceAccessFilter}.
 * For the other results it is derived from the verdict and the resource IDs of the authorization,
 * and it is {@code null} for an allowed result that is expressed through resource property names
 * only.
 *
 * <p><strong>For an allowed result that is not a wildcard and carries a filter other than the ID
 * terms of {@code authorization}, the legacy fields do not describe the access:</strong> {@code
 * authorization} lists no resource IDs of the accessible resources and {@code wildcard} is {@code
 * false}. Consumers must use the {@link #filter() filter}.
 *
 * <p>Produced by {@link ResourceAccessProvider} implementations and consumed by search backends to
 * determine query-level resource filters.
 *
 * @param filter the declarative description of the accessible resources, or {@code null} if the
 *     result carries none
 */
public record ResourceAccess(
    boolean allowed,
    boolean wildcard,
    RequiredAuthorization<?> authorization,
    ResourceAccessFilter filter) {

  public ResourceAccess {
    Objects.requireNonNull(authorization, "Authorization must not be null");
    if (!allowed && filter != null && !(filter instanceof ResourceAccessFilter.None)) {
      throw new IllegalArgumentException("A denied access must not carry a filter that allows");
    }
    if (allowed && filter instanceof ResourceAccessFilter.None) {
      throw new IllegalArgumentException("An allowed access must not carry the none filter");
    }
    if (wildcard
        && (!allowed || (filter != null && !(filter instanceof ResourceAccessFilter.All)))) {
      throw new IllegalArgumentException("A wildcard access must be allowed and match all");
    }
  }

  public ResourceAccess(
      final boolean allowed, final boolean wildcard, final RequiredAuthorization<?> authorization) {
    this(allowed, wildcard, authorization, derivedFilter(allowed, wildcard, authorization));
  }

  private static ResourceAccessFilter derivedFilter(
      final boolean allowed, final boolean wildcard, final RequiredAuthorization<?> authorization) {
    if (!allowed) {
      return new ResourceAccessFilter.None();
    }
    if (wildcard) {
      return new ResourceAccessFilter.All();
    }
    if (authorization != null && authorization.hasAnyResourceIds()) {
      return new ResourceAccessFilter.AnyOf(
          List.of(
              new ResourceAccessFilter.Term(Set.copyOf(authorization.resourceIds()), List.of())));
    }
    return null;
  }

  /** Returns {@code true} when the principal does not have access to the resource. */
  public boolean denied() {
    return !allowed;
  }

  /**
   * Creates an access result indicating the principal is permitted to access the specific resource
   * (non-wildcard grant).
   */
  public static ResourceAccess allowed(final RequiredAuthorization<?> authorization) {
    return new ResourceAccess(true, false, authorization);
  }

  /** Creates an access result indicating the principal is not permitted to access the resource. */
  public static ResourceAccess denied(final RequiredAuthorization<?> authorization) {
    return new ResourceAccess(false, false, authorization);
  }

  /**
   * Creates an access result indicating the principal is permitted to access the resources
   * described by {@code filter}.
   */
  public static ResourceAccess allowed(
      final RequiredAuthorization<?> authorization, final ResourceAccessFilter filter) {
    return new ResourceAccess(true, false, authorization, filter);
  }

  /**
   * Creates an access result indicating the principal holds a wildcard grant covering all resources
   * of the relevant type.
   */
  public static ResourceAccess wildcard(final RequiredAuthorization<?> authorization) {
    return new ResourceAccess(true, true, authorization);
  }
}
