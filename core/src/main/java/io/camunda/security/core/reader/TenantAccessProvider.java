/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.reader;

import io.camunda.security.api.model.CamundaAuthentication;

/**
 * Resolves whether a principal represented by a {@link CamundaAuthentication} has access to a
 * tenant.
 *
 * <p>Mirrors the structure of {@link ResourceAccessProvider} for the tenant dimension.
 * Implementations query the authorization store and return a {@link TenantAccess} verdict that
 * records the allowed tenant IDs and whether access was granted via a wildcard.
 */
public interface TenantAccessProvider {

  /**
   * Resolves the full set of tenant IDs the principal is permitted to access. Used to populate
   * {@link ResourceAccessChecks} before a query is executed so the search backend can add
   * tenant-scoping filters.
   *
   * @param authentication the resolved authentication context of the caller
   */
  TenantAccess resolveTenantAccess(CamundaAuthentication authentication);

  /**
   * Evaluates whether the principal has access to the tenant associated with the given {@code
   * resource} document. Called per-document during result streaming.
   *
   * @param authentication the resolved authentication context of the caller
   * @param resource the specific document whose tenant membership is checked
   */
  <T> TenantAccess hasTenantAccess(CamundaAuthentication authentication, T resource);

  /**
   * Evaluates whether the principal has access to the tenant identified by {@code tenantId}.
   *
   * @param authentication the resolved authentication context of the caller
   * @param tenantId the ID of the tenant to check
   */
  TenantAccess hasTenantAccessByTenantId(CamundaAuthentication authentication, String tenantId);
}
