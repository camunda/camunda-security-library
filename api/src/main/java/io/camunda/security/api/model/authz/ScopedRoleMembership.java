/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import java.io.Serializable;
import java.util.Objects;

/**
 * A role membership restricted to one scope. The role applies to a resource only when the
 * resource's scope ID, as returned by a {@code ResourceScopeExtractor}, equals {@code scopeId}.
 *
 * <p>The scope ID is opaque to the library; the host decides what a scope is (e.g. a workspace).
 *
 * @param roleId the ID of the role held within the scope
 * @param scopeId the opaque ID of the scope the role is restricted to
 */
public record ScopedRoleMembership(String roleId, String scopeId) implements Serializable {

  public ScopedRoleMembership {
    Objects.requireNonNull(roleId, "roleId");
    Objects.requireNonNull(scopeId, "scopeId");
  }
}
