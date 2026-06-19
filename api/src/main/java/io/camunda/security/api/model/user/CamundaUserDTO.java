/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.user;

import java.util.List;

/**
 * Public view of the authenticated user returned by {@code CamundaUserPort#getCurrentUser()}
 * (defined in the core module). The record is framework-free and uses only primitives, so it carries
 * no dependency on host search-domain entities.
 *
 * <p>The {@code c8Links} map keys are application identifiers (e.g. {@code "operate"}, {@code
 * "tasklist"}); hosts that store stronger types convert them to strings at the boundary.
 */
public record CamundaUserDTO(
    String displayName,
    String username,
    String email,
    List<String> authorizedComponents,
    List<String> tenants,
    List<String> groups,
    List<String> roles,
    String salesPlanType,
    boolean canLogout) {

  public CamundaUserDTO {
    authorizedComponents = authorizedComponents != null ? authorizedComponents : List.of();
    tenants = tenants != null ? tenants : List.of();
    groups = groups != null ? groups : List.of();
    roles = roles != null ? roles : List.of();
  }
}
