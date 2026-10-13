/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static io.camunda.security.api.model.policy.PolicyValidation.setOrEmpty;

import io.camunda.security.api.model.authz.PermissionType;
import java.util.Objects;
import java.util.Set;

/**
 * The complete set of permissions granted for one {@link PolicyAuthorizationKey}. A change set
 * carries at most one authorization per key.
 */
public record PolicyAuthorization(PolicyAuthorizationKey key, Set<PermissionType> permissions) {

  public PolicyAuthorization {
    Objects.requireNonNull(key, "key must not be null");
    permissions = setOrEmpty(permissions);
    if (permissions.isEmpty()) {
      throw new IllegalArgumentException("permissions must not be empty");
    }
    final Set<PermissionType> supported = key.resourceType().getSupportedPermissionTypes();
    for (final PermissionType permission : permissions) {
      if (!supported.contains(permission)) {
        throw new IllegalArgumentException(
            "Permission " + permission + " is not supported by " + key.resourceType());
      }
    }
  }
}
