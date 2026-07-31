/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import java.util.Set;

/**
 * Inbound port for authorization management. Hub calls this to assign or revoke resource
 * authorizations for a given owner.
 */
public interface AuthorizationManagementPort {

  void assign(
      AuthorizationOwnerType ownerType,
      String ownerId,
      ResourceType resourceType,
      String resourceId,
      Set<PermissionType> permissionTypes);

  void revoke(
      AuthorizationOwnerType ownerType,
      String ownerId,
      ResourceType resourceType,
      String resourceId,
      Set<PermissionType> permissionTypes);
}
