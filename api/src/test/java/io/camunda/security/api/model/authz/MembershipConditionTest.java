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

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class MembershipConditionTest {

  @Test
  void shouldKeepAttributeAndOperand() {
    // given
    final var operand = new Operand.Values(Set.of("payments"));

    // when
    final var condition = new MembershipCondition(ResourceAttribute.WORKSPACE, operand);

    // then
    assertThat(condition.attribute()).isEqualTo(ResourceAttribute.WORKSPACE);
    assertThat(condition.operand()).isEqualTo(operand);
  }

  @Test
  void shouldRejectNullAttribute() {
    assertThatThrownBy(() -> new MembershipCondition(null, new Operand.Values(Set.of("payments"))))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldRejectNullOperand() {
    assertThatThrownBy(() -> new MembershipCondition(ResourceAttribute.WORKSPACE, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldCopyValues() {
    // given
    final var values = new HashSet<>(Set.of("payments"));
    final var operand = new Operand.Values(values);

    // when
    values.add("lending");

    // then
    assertThat(operand.values()).containsExactly("payments");
  }

  @Test
  void shouldRejectNoValues() {
    // a condition without values can never be met
    assertThatThrownBy(() -> new Operand.Values(Set.of()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldRejectNullValues() {
    assertThatThrownBy(() -> new Operand.Values(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldRejectANullValue() {
    final var values = new HashSet<String>();
    values.add(null);

    assertThatThrownBy(() -> new Operand.Values(values)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldRejectNullPrincipalAttribute() {
    assertThatThrownBy(() -> new Operand.Principal(null)).isInstanceOf(NullPointerException.class);
  }
}
