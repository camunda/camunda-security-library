/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.CamundaAuthentication;

/**
 * {@link TenantAccessProvider} used when multi-tenancy checks are disabled: every principal holds a
 * wildcard grant covering all tenants, regardless of authentication.
 */
public final class DisabledTenantAccessProvider implements TenantAccessProvider {

  @Override
  public TenantAccess resolveTenantAccess(final CamundaAuthentication authentication) {
    return TenantAccess.wildcard(null);
  }

  @Override
  public <T> TenantAccess hasTenantAccess(
      final CamundaAuthentication authentication, final T resource) {
    return TenantAccess.wildcard(null);
  }

  @Override
  public TenantAccess hasTenantAccessByTenantId(
      final CamundaAuthentication authentication, final String tenantId) {
    return TenantAccess.wildcard(null);
  }
}
