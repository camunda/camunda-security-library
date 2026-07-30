/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

/**
 * A resource whose access is scoped to a single owning tenant.
 *
 * <p>Implemented by entities that carry a tenant id, so that a {@link TenantAccessProvider} can
 * derive tenant access for the resource from {@link #tenantId()} without knowing the concrete
 * resource type. Tenant-ownership is a security property of the entity, which is why this contract
 * lives alongside {@link TenantAccess} rather than in a consumer's read model.
 */
public interface TenantOwnedEntity {

  String tenantId();

  default boolean hasTenantScope() {
    return true;
  }
}
