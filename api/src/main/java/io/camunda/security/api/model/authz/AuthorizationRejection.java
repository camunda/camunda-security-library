/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

/**
 * Describes why an authorization check was rejected.
 *
 * <p>Two subtypes:
 *
 * <ul>
 *   <li>{@link Tenant} — the principal does not have access to the required tenant
 *   <li>{@link Permission} — the principal lacks the required permission on the resource
 * </ul>
 */
public sealed interface AuthorizationRejection
    permits AuthorizationRejection.Tenant, AuthorizationRejection.Permission {

  record Tenant(String tenantId) implements AuthorizationRejection {}

  record Permission(
      AuthorizationResourceType resourceType, PermissionType permissionType, String resourceId)
      implements AuthorizationRejection {}
}
