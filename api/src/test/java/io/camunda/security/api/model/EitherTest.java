/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.NoSuchElementException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class EitherTest {

  @Nested
  class LeftVariant {
    @Test
    void factoryCreatesLeft() {
      assertThat(Either.left("err").isLeft()).isTrue();
    }

    @Test
    void isRightReturnsFalse() {
      assertThat(Either.left("err").isRight()).isFalse();
    }

    @Test
    void leftValueReturnsWrappedValue() {
      assertThat(Either.<String, Integer>left("err").leftValue()).isEqualTo("err");
    }

    @Test
    void rightValueThrowsNoSuchElement() {
      assertThatThrownBy(() -> Either.left("err").rightValue())
          .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void nullIsValidLeftValue() {
      assertThat(Either.<Void, Integer>left(null).leftValue()).isNull();
    }
  }

  @Nested
  class RightVariant {
    @Test
    void factoryCreatesRight() {
      assertThat(Either.right(42).isRight()).isTrue();
    }

    @Test
    void isLeftReturnsFalse() {
      assertThat(Either.right(42).isLeft()).isFalse();
    }

    @Test
    void rightValueReturnsWrappedValue() {
      assertThat(Either.<String, Integer>right(42).rightValue()).isEqualTo(42);
    }

    @Test
    void leftValueThrowsNoSuchElement() {
      assertThatThrownBy(() -> Either.right(42).leftValue())
          .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void nullIsValidRightValue() {
      // Void right type uses null as canonical value
      assertThat(Either.<String, Void>right(null).rightValue()).isNull();
    }
  }
}
