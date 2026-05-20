/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class MembershipsTest {

  @Test
  void emptyMembershipsHaveNoMembers() {
    final var m = Memberships.empty();
    assertThat(m.groups().groupIds()).isEmpty();
    assertThat(m.roles().roleIds()).isEmpty();
    assertThat(m.tenants().tenantIds()).isEmpty();
    assertThat(m.mappingRules().mappingRuleIds()).isEmpty();
  }

  @Test
  void membershipsHoldProvidedValues() {
    final var m =
        new Memberships(
            new Groups(List.of("g1")),
            new Roles(List.of("r1")),
            new Tenants(List.of("t1")),
            new MappingRules(List.of("mr1")));
    assertThat(m.groups().groupIds()).containsExactly("g1");
    assertThat(m.roles().roleIds()).containsExactly("r1");
    assertThat(m.tenants().tenantIds()).containsExactly("t1");
    assertThat(m.mappingRules().mappingRuleIds()).containsExactly("mr1");
  }
}
