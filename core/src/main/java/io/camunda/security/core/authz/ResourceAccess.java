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
 * <p>Produced by {@link ResourceAccessProvider} implementations and consumed by search backends to
 * determine query-level resource filters.
 *
 * <p>{@link #filter()} describes the accessible resources. A result created without a filter
 * derives one: {@link ResourceAccessFilter.None} when denied, {@link ResourceAccessFilter.All} for
 * a wildcard, and the resource IDs of {@code authorization} otherwise. It is {@code null} for an
 * allowed result that names no resource IDs, for example one expressed through resource property
 * names.
 *
 * <p><strong>When a result carries conditional terms, the other fields do not describe the
 * access:</strong> {@code wildcard} is {@code false} and {@code authorization} lists no resource
 * IDs for the resources that the conditions match. Use {@link #filter()}. {@link
 * ConditionalResourceAccessProvider} creates such results.
 *
 * @param allowed whether the principal may access the resource, or for a list, at least one
 *     resource
 * @param wildcard whether the principal may access every resource
 * @param authorization the requirement that produced this result
 * @param filter the accessible resources, or {@code null} if this result does not describe them
 */
public record ResourceAccess(
    boolean allowed,
    boolean wildcard,
    RequiredAuthorization<?> authorization,
    ResourceAccessFilter filter) {

  public ResourceAccess {
    Objects.requireNonNull(authorization, "Authorization must not be null");
    if (!allowed && !(filter instanceof ResourceAccessFilter.None)) {
      throw new IllegalArgumentException("A denied access must carry the None filter");
    }
    if (allowed && filter instanceof ResourceAccessFilter.None) {
      throw new IllegalArgumentException("An allowed access must not carry the None filter");
    }
    if (wildcard != (filter instanceof ResourceAccessFilter.All)) {
      throw new IllegalArgumentException(
          "A wildcard access must carry the All filter, and only a wildcard access may");
    }
  }

  /** Creates a result whose {@link #filter()} is derived from the other fields. */
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
      return ResourceAccessFilter.anyOf(
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

  /**
   * Creates the result for the resources that {@code filter} describes: denied for {@link
   * ResourceAccessFilter.None}, a wildcard for {@link ResourceAccessFilter.All}, and allowed with
   * {@code filter} for {@link ResourceAccessFilter.AnyOf}.
   */
  public static ResourceAccess of(
      final RequiredAuthorization<?> authorization, final ResourceAccessFilter filter) {
    return switch (filter) {
      case ResourceAccessFilter.None none -> denied(authorization);
      case ResourceAccessFilter.All all -> wildcard(authorization);
      case ResourceAccessFilter.AnyOf anyOf ->
          new ResourceAccess(true, false, authorization, anyOf);
    };
  }

  /** Creates an access result indicating the principal is not permitted to access the resource. */
  public static ResourceAccess denied(final RequiredAuthorization<?> authorization) {
    return new ResourceAccess(false, false, authorization);
  }

  /**
   * Creates an access result indicating the principal holds a wildcard grant covering all resources
   * of the relevant type.
   */
  public static ResourceAccess wildcard(final RequiredAuthorization<?> authorization) {
    return new ResourceAccess(true, true, authorization);
  }
}
