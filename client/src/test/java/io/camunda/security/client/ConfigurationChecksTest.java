/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class ConfigurationChecksTest {

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {"", " ", "\t"})
  void requireTextRejectsMissingOrBlankValuesNamingTheField(final String value) {
    assertThatThrownBy(() -> ConfigurationChecks.requireText(value, "clientId"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("clientId must not be blank");
  }

  @Test
  void requireTextAcceptsText() {
    assertThatCode(() -> ConfigurationChecks.requireText("id", "clientId"))
        .doesNotThrowAnyException();
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {"", " ", "\t", "\u2003"})
  void isBlankIsTrueForNullEmptyAndWhitespace(final String value) {
    assertThat(ConfigurationChecks.isBlank(value)).isTrue();
  }

  @Test
  void isBlankIsFalseForText() {
    assertThat(ConfigurationChecks.isBlank("a")).isFalse();
    assertThat(ConfigurationChecks.isBlank(" a ")).isFalse();
  }
}
