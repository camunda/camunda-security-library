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
    assertThat(m.groupIds()).isEmpty();
    assertThat(m.roleIds()).isEmpty();
    assertThat(m.tenantIds()).isEmpty();
    assertThat(m.mappingRuleIds()).isEmpty();
  }

  @Test
  void membershipsHoldProvidedValues() {
    final var m = new Memberships(List.of("g1"), List.of("r1"), List.of("t1"), List.of("mr1"));
    assertThat(m.groupIds()).containsExactly("g1");
    assertThat(m.roleIds()).containsExactly("r1");
    assertThat(m.tenantIds()).containsExactly("t1");
    assertThat(m.mappingRuleIds()).containsExactly("mr1");
  }
}
