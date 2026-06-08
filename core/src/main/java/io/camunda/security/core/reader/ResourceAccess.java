/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.reader;

import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.Objects;

/**
 * The result of evaluating whether a principal has access to a specific resource.
 *
 * <p>Carries the verdict ({@link #allowed()}), whether it was granted via a wildcard scope ({@link
 * #wildcard()}), and the {@link RequiredAuthorization} that produced the result so callers can
 * trace which requirement was evaluated.
 *
 * <p>Produced by {@link ResourceAccessProvider} implementations and consumed by search backends to
 * determine query-level resource filters.
 */
public record ResourceAccess(
    boolean allowed, boolean wildcard, RequiredAuthorization<?> authorization) {

  public ResourceAccess {
    Objects.requireNonNull(authorization, "Authorization must not be null");
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
   * Creates an access result indicating the principal holds a wildcard grant covering all resources
   * of the relevant type.
   */
  public static ResourceAccess wildcard(final RequiredAuthorization<?> authorization) {
    return new ResourceAccess(true, true, authorization);
  }
}
