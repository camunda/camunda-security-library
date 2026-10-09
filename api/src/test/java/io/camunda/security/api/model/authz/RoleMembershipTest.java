/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class RoleMembershipTest {

  private static final Condition WORKSPACE_W1 =
      new Condition(ResourceAttribute.WORKSPACE, new Operand.Values(Set.of("w1")));

  @Test
  void constructorKeepsRoleIdAndConditions() {
    final var membership = new RoleMembership("editor", List.of(WORKSPACE_W1));

    assertThat(membership.roleId()).isEqualTo("editor");
    assertThat(membership.conditions()).containsExactly(WORKSPACE_W1);
  }

  @Test
  void constructorNormalizesNullConditionsToEmpty() {
    assertThat(new RoleMembership("editor", null).conditions()).isEmpty();
  }

  @Test
  void constructorCopiesConditionsImmutably() {
    final var mutable = new ArrayList<>(List.of(WORKSPACE_W1));

    final var membership = new RoleMembership("editor", mutable);
    mutable.clear();

    assertThat(membership.conditions()).containsExactly(WORKSPACE_W1);
    assertThatThrownBy(() -> membership.conditions().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void constructorWithNullRoleIdThrowsNullPointerException() {
    assertThatThrownBy(() -> new RoleMembership(null, List.of()))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void constructorRejectsPrincipalOperands() {
    final var principalCondition =
        new Condition(
            ResourceAttribute.ASSIGNEE, new Operand.Principal(PrincipalAttribute.USERNAME));

    assertThatThrownBy(() -> new RoleMembership("editor", List.of(principalCondition)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("ASSIGNEE");
  }

  @Test
  void membershipSurvivesSerialization() throws Exception {
    final var membership = new RoleMembership("editor", List.of(WORKSPACE_W1));

    final var bytes = new ByteArrayOutputStream();
    try (var out = new ObjectOutputStream(bytes)) {
      out.writeObject(membership);
    }
    try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      assertThat(in.readObject()).isEqualTo(membership);
    }
  }
}
