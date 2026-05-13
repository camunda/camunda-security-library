/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;

/**
 * Inbound port for resource-permission decisions. Answers "does this principal have this {@link
 * PermissionType} on the resource of this {@link ResourceType} with this id?".
 *
 * <p>Implementations may apply caching, instrumentation, or alternative matching semantics over the
 * host's authorization records. The library provides a default implementation that delegates to
 * {@link io.camunda.security.core.port.out.AuthorizationRepositoryPort} for data and matches grants
 * by resource id and permission across the principal's authorizations.
 */
public interface ResourcePermissionPort {

  boolean hasPermission(
      CamundaAuthentication authentication,
      ResourceType resourceType,
      String resourceId,
      PermissionType permissionType);
}
