/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import java.util.List;

/**
 * The result of evaluating whether a principal has access to a specific tenant.
 *
 * <p>Mirrors the structure of {@link ResourceAccess} for the tenant dimension: carries the verdict
 * ({@link #allowed()}), whether it was granted via a wildcard scope ({@link #wildcard()}), and the
 * tenant IDs that were resolved.
 *
 * <p>Produced by {@link TenantAccessProvider} implementations and consumed by search backends to
 * add tenant-scoping filters to queries.
 */
public record TenantAccess(boolean allowed, boolean wildcard, List<String> tenantIds) {

  /** Returns {@code true} when the principal does not have access to the tenant. */
  public boolean denied() {
    return !allowed;
  }

  /**
   * Creates an access result indicating the principal is permitted to access the given tenants
   * (non-wildcard grant).
   */
  public static TenantAccess allowed(final List<String> tenantIds) {
    return new TenantAccess(true, false, tenantIds);
  }

  /** Creates an access result indicating the principal is not permitted to access the tenants. */
  public static TenantAccess denied(final List<String> tenantIds) {
    return new TenantAccess(false, false, tenantIds);
  }

  /**
   * Creates an access result indicating the principal holds a wildcard grant covering all tenants.
   */
  public static TenantAccess wildcard(final List<String> tenantIds) {
    return new TenantAccess(true, true, tenantIds);
  }
}
