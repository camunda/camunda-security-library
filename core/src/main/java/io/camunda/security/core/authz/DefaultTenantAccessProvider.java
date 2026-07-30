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
 * The canonical {@link TenantAccessProvider}. It derives the verdict purely from the tenant ids
 * carried on the {@link CamundaAuthentication} ({@link
 * CamundaAuthentication#authenticatedTenantIds()}) — no authorization store is queried. For a
 * resource, {@link #hasTenantAccess(CamundaAuthentication, Object)} extracts the owning tenant via
 * {@link TenantOwnedEntity}; resources that are not tenant-owned require no tenant check and are
 * granted.
 *
 * <p>This provider is anonymous-agnostic: it does not special-case anonymous authentications.
 * Callers that grant anonymous requests unconditional access (e.g. the engine write-path, or the
 * search read-path's anonymous controller) handle that before delegating here.
 */
public final class DefaultTenantAccessProvider implements TenantAccessProvider {

  @Override
  public TenantAccess resolveTenantAccess(final CamundaAuthentication authentication) {
    final var authenticatedTenantIds = authentication.authenticatedTenantIds();
    if (authenticatedTenantIds == null || authenticatedTenantIds.isEmpty()) {
      return TenantAccess.denied(null);
    }
    return TenantAccess.allowed(authenticatedTenantIds);
  }

  @Override
  public <T> TenantAccess hasTenantAccess(
      final CamundaAuthentication authentication, final T resource) {
    if (resource instanceof final TenantOwnedEntity tenantOwnedEntity
        && tenantOwnedEntity.hasTenantScope()) {
      return hasTenantAccessByTenantId(authentication, tenantOwnedEntity.tenantId());
    }
    // if not tenant-owned, no tenant check needed => access granted
    return TenantAccess.allowed(List.of());
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
