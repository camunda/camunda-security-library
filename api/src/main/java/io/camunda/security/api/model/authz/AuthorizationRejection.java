/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import java.util.Set;

/**
 * Describes why an authorization check was rejected.
 *
 * <p>Three subtypes:
 *
 * <ul>
 *   <li>{@link Tenant} — the principal does not have access to the required tenant
 *   <li>{@link Permission} — the principal lacks the required permission on the resource
 *   <li>{@link Property} — the principal lacks a stored property-scoped grant (or a matching
 *       evaluator) for any of the declared resource properties
 * </ul>
 */
public sealed interface AuthorizationRejection
    permits AuthorizationRejection.Tenant,
        AuthorizationRejection.Permission,
        AuthorizationRejection.Property {

  record Tenant(String tenantId) implements AuthorizationRejection {}

  record Permission(
      AuthorizationResourceType resourceType, PermissionType permissionType, String resourceId)
      implements AuthorizationRejection {}

  record Property(
      AuthorizationResourceType resourceType,
      PermissionType permissionType,
      Set<String> propertyNames)
      implements AuthorizationRejection {}
}
