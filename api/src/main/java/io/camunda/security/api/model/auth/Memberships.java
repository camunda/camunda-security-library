/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.auth;

import java.util.List;

/**
 * Group, role, tenant, and mapping-rule memberships resolved for a principal by the host's {@code
 * MembershipPort} implementation.
 */
public record Memberships(
    List<String> groupIds,
    List<String> roleIds,
    List<String> tenantIds,
    List<String> mappingRuleIds) {

  public static Memberships empty() {
    return new Memberships(List.of(), List.of(), List.of(), List.of());
  }
}
