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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class MembershipConditionTest {

  @Test
  void shouldKeepAttributeAndOperand() {
    // given
    final var operand = new Operand.Equals("payments");

    // when
    final var condition = new MembershipCondition(ResourceAttribute.WORKSPACE_ID, operand);

    // then
    assertThat(condition.attribute()).isEqualTo(ResourceAttribute.WORKSPACE_ID);
    assertThat(condition.operand()).isEqualTo(operand);
  }

  @Test
  void shouldRejectNullAttribute() {
    assertThatThrownBy(() -> new MembershipCondition(null, new Operand.Equals("payments")))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldRejectNullOperand() {
    assertThatThrownBy(() -> new MembershipCondition(ResourceAttribute.WORKSPACE_ID, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldRejectNullValue() {
    assertThatThrownBy(() -> new Operand.Equals(null)).isInstanceOf(NullPointerException.class);
  }

  @ParameterizedTest
  @ValueSource(strings = {"", " "})
  void shouldRejectBlankValue(final String value) {
    // a blank value can never be met
    assertThatThrownBy(() -> new Operand.Equals(value))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldKeepAWildcardAsALiteralValue() {
    // "*" is not a wildcard; a membership on every resource is a global role membership
    assertThat(new Operand.Equals("*").value()).isEqualTo("*");
  }
}
