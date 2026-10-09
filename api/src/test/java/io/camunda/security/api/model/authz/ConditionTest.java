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
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ConditionTest {

  @Test
  void conditionKeepsAttributeAndOperand() {
    final var operand = new Operand.Values(Set.of("w1"));

    final var condition = new Condition(ResourceAttribute.WORKSPACE, operand);

    assertThat(condition.attribute()).isEqualTo(ResourceAttribute.WORKSPACE);
    assertThat(condition.operand()).isEqualTo(operand);
  }

  @Test
  void conditionWithNullAttributeThrowsNullPointerException() {
    assertThatThrownBy(() -> new Condition(null, new Operand.Values(Set.of("w1"))))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void conditionWithNullOperandThrowsNullPointerException() {
    assertThatThrownBy(() -> new Condition(ResourceAttribute.WORKSPACE, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void valuesOperandCopiesItsValuesImmutably() {
    final var mutable = new HashSet<>(Set.of("w1"));

    final var operand = new Operand.Values(mutable);
    mutable.add("w2");

    assertThat(operand.values()).containsExactly("w1");
    assertThatThrownBy(() -> operand.values().add("w3"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void valuesOperandWithNullValuesThrowsNullPointerException() {
    assertThatThrownBy(() -> new Operand.Values(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void principalOperandWithNullAttributeThrowsNullPointerException() {
    assertThatThrownBy(() -> new Operand.Principal(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void conditionWithEitherOperandSurvivesSerialization() throws Exception {
    final var literal =
        new Condition(ResourceAttribute.WORKSPACE, new Operand.Values(Set.of("w1")));
    final var principal =
        new Condition(
            ResourceAttribute.CANDIDATE_GROUPS,
            new Operand.Principal(PrincipalAttribute.GROUP_IDS));

    for (final var condition : new Condition[] {literal, principal}) {
      final var bytes = new ByteArrayOutputStream();
      try (var out = new ObjectOutputStream(bytes)) {
        out.writeObject(condition);
      }
      try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
        assertThat(in.readObject()).isEqualTo(condition);
      }
    }
  }
}
