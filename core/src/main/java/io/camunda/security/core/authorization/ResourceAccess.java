/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authorization;

import java.util.Objects;
import java.util.Set;

/**
 * Result of an authorization decision: {@link Allowed} (with the granted resource ids), {@link
 * Wildcard} (granted for every resource of this type), or {@link Denied}.
 */
public sealed interface ResourceAccess
    permits ResourceAccess.Allowed, ResourceAccess.Wildcard, ResourceAccess.Denied {

  default boolean allowed() {
    return this instanceof Allowed || this instanceof Wildcard;
  }

  /**
   * Access granted for the listed resource ids. {@code grantedResourceIds} must be non-empty — use
   * {@link Wildcard} for an unbounded grant or {@link Denied} when nothing is granted.
   */
  record Allowed(Set<String> grantedResourceIds) implements ResourceAccess {
    public Allowed {
      Objects.requireNonNull(grantedResourceIds, "grantedResourceIds");
      if (grantedResourceIds.isEmpty()) {
        throw new IllegalArgumentException(
            "Allowed.grantedResourceIds must not be empty — use Wildcard or Denied instead.");
      }
      grantedResourceIds = Set.copyOf(grantedResourceIds);
    }
  }

  /** Access granted for every resource id of this resource type (no need to enumerate). */
  record Wildcard() implements ResourceAccess {}

  /** Access denied. */
  record Denied() implements ResourceAccess {}
}
