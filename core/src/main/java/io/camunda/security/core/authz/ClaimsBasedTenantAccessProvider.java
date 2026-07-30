/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.CamundaAuthentication;
import java.util.List;

/**
 * A {@link TenantAccessProvider} that derives the verdict purely from the tenant IDs carried on the
 * {@link CamundaAuthentication} ({@link CamundaAuthentication#authenticatedTenantIds()}) — no
 * authorization store is queried. Suitable for callers such as the process engine that already hold
 * the principal's authorized tenants in the authentication context.
 *
 * <p>Engine-specific skip/default policy (anonymous → wildcard, multi-tenancy disabled → default
 * tenant, no principal → denied) is intentionally out of scope here; callers that need it layer it
 * on top of this provider.
 */
public class ClaimsBasedTenantAccessProvider implements TenantAccessProvider {

  @Override
  public TenantAccess resolveTenantAccess(final CamundaAuthentication authentication) {
    final var authenticatedTenantIds = authentication.authenticatedTenantIds();
    if (authenticatedTenantIds == null || authenticatedTenantIds.isEmpty()) {
      return TenantAccess.denied(null);
    }
    return TenantAccess.allowed(authenticatedTenantIds);
  }

  /**
   * Not supported by the claims-based provider: extracting a tenant from an arbitrary resource
   * requires a resource-type-aware abstraction (e.g. the search layer's {@code TenantOwnedEntity}),
   * which is not available in {@code core}. Callers needing per-document resolution should use a
   * resource-aware provider such as the search module's {@code DefaultTenantAccessProvider}, or
   * extract the tenant id themselves and call {@link #hasTenantAccessByTenantId}.
   */
  @Override
  public <T> TenantAccess hasTenantAccess(
      final CamundaAuthentication authentication, final T resource) {
    throw new UnsupportedOperationException(
        "ClaimsBasedTenantAccessProvider cannot resolve the tenant of an arbitrary resource; "
            + "use a resource-aware TenantAccessProvider or hasTenantAccessByTenantId instead.");
  }

  @Override
  public TenantAccess hasTenantAccessByTenantId(
      final CamundaAuthentication authentication, final String tenantId) {
    final var authenticatedTenantIds = authentication.authenticatedTenantIds();
    final var tenantIdAsList = List.of(tenantId);

    if (authenticatedTenantIds == null || authenticatedTenantIds.isEmpty()) {
      return TenantAccess.denied(tenantIdAsList);
    }

    return authenticatedTenantIds.contains(tenantId)
        ? TenantAccess.allowed(tenantIdAsList)
        : TenantAccess.denied(tenantIdAsList);
  }
}
