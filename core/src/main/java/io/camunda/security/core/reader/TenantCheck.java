/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.reader;

import java.util.List;

/**
 * Describes whether tenant-level scoping should be applied to a query or operation, and if so,
 * which tenant IDs the principal is permitted to access.
 *
 * <p>When {@link #enabled()} is {@code false} the tenant check is bypassed and all tenants are
 * accessible. When enabled, {@link #tenantIds()} carries the resolved set of tenant IDs that should
 * be used as query filters.
 *
 * <p>Used alongside {@link AuthorizationCheck} inside {@link ResourceAccessChecks} to assemble the
 * full access-control picture for a single query.
 */
public record TenantCheck(boolean enabled, List<String> tenantIds) {

  /**
   * Creates an enabled check scoping access to the supplied tenant IDs.
   *
   * @param tenantIds the tenant IDs the principal is permitted to access; must not be {@code null}
   */
  public static TenantCheck enabled(final List<String> tenantIds) {
    return new TenantCheck(true, tenantIds);
  }

  /** Creates a disabled check — tenant scoping is not enforced and all tenants are accessible. */
  public static TenantCheck disabled() {
    return new TenantCheck(false, null);
  }

  /**
   * Returns {@code true} when no tenant filter needs to be applied to a query. This is the case
   * when the check is disabled (tenant isolation off) or when at least one tenant ID is present for
   * the search backend to use as a filter.
   */
  public boolean hasAnyTenantAccess() {
    return !enabled || hasAnyTenantIdAccess();
  }

  private boolean hasAnyTenantIdAccess() {
    return tenantIds != null && !tenantIds.isEmpty();
  }
}
