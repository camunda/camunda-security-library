/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import java.util.Objects;
import java.util.Set;

/**
 * A granted authorization record sourced from the host's authorization store: the principal has the
 * listed {@code permissionTypes} on the {@code resourceId} of {@code resourceType}.
 *
 * <p>This is the "data shape" of an authorization — what the host's data store stores. It carries
 * no behaviour of its own; the unified authorization check operates on {@code AuthorizationScope}s
 * resolved via {@code AuthorizationScopeRepositoryPort}, not on instances of this record.
 */
public record Authorization(
    ResourceType resourceType, String resourceId, Set<PermissionType> permissionTypes) {

  public Authorization {
    Objects.requireNonNull(resourceType, "resourceType");
    Objects.requireNonNull(resourceId, "resourceId");
    permissionTypes = permissionTypes == null ? Set.of() : Set.copyOf(permissionTypes);
  }
}
