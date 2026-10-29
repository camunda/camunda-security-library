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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ConditionalMembershipTest {

  private static final MembershipCondition IN_PAYMENTS =
      new MembershipCondition(ResourceAttribute.WORKSPACE, new Operand.Values(Set.of("payments")));

  @Test
  void shouldKeepIdAndConditions() {
    // when
    final var membership = new ConditionalMembership("reviewer", List.of(IN_PAYMENTS));

    // then
    assertThat(membership.id()).isEqualTo("reviewer");
    assertThat(membership.conditions()).containsExactly(IN_PAYMENTS);
  }

  @Test
  void shouldCopyConditions() {
    // given
    final var conditions = new ArrayList<>(List.of(IN_PAYMENTS));
    final var membership = new ConditionalMembership("reviewer", conditions);

    // when
    conditions.clear();

    // then
    assertThat(membership.conditions()).containsExactly(IN_PAYMENTS);
    assertThatThrownBy(() -> membership.conditions().add(IN_PAYMENTS))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void shouldRejectNoConditions() {
    // a membership without conditions is global and belongs in the ID lists
    assertThatThrownBy(() -> new ConditionalMembership("reviewer", List.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("reviewer");
  }

  @Test
  void shouldRejectNullConditions() {
    assertThatThrownBy(() -> new ConditionalMembership("reviewer", null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldRejectANullCondition() {
    final var conditions = new ArrayList<MembershipCondition>();
    conditions.add(null);

    assertThatThrownBy(() -> new ConditionalMembership("reviewer", conditions))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldRejectNullId() {
    assertThatThrownBy(() -> new ConditionalMembership(null, List.of(IN_PAYMENTS)))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldRejectBlankId() {
    assertThatThrownBy(() -> new ConditionalMembership(" ", List.of(IN_PAYMENTS)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldAcceptAPrincipalOperand() {
    // when
    final var ownTasks =
        new MembershipCondition(
            ResourceAttribute.ASSIGNEE, new Operand.Principal(PrincipalAttribute.USERNAME));
    final var membership = new ConditionalMembership("reviewer", List.of(IN_PAYMENTS, ownTasks));

    // then
    assertThat(membership.conditions()).containsExactly(IN_PAYMENTS, ownTasks);
  }
}
