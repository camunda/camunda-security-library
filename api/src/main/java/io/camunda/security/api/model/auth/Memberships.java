/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.auth;

import java.util.List;

public record Memberships(Groups groups, Roles roles, Tenants tenants, MappingRules mappingRules) {

  public static Memberships empty() {
    return new Memberships(
        new Groups(List.of()),
        new Roles(List.of()),
        new Tenants(List.of()),
        new MappingRules(List.of()));
  }
}
