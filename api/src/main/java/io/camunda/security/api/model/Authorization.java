/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model;

import java.util.Objects;
import java.util.Set;

/**
 * A granted authorization record returned by an {@code AuthorizationRepositoryPort}: the principal
 * has the listed {@code permissionTypes} on the {@code resourceId} of {@code resourceType}.
 *
 * <p>This is the "data shape" of an authorization — what the host's data store stores. The library
 * aggregates these records across the principal's identities (user, groups, roles, mapping rules)
 * and matches them against requested permissions to produce a yes/no decision.
 */
public record Authorization(
    ResourceType resourceType, String resourceId, Set<PermissionType> permissionTypes) {

  public Authorization {
    Objects.requireNonNull(resourceType, "resourceType");
    Objects.requireNonNull(resourceId, "resourceId");
    permissionTypes = permissionTypes == null ? Set.of() : Set.copyOf(permissionTypes);
  }
}
