/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.initialization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class ConfiguredMappingRuleTest {

  @Test
  void shouldStoreAllFieldsFromConstructor() {
    final var rule = new ConfiguredMappingRule("rule-1", "claim", "value");

    assertThat(rule.mappingRuleId()).isEqualTo("rule-1");
    assertThat(rule.claimName()).isEqualTo("claim");
    assertThat(rule.claimValue()).isEqualTo("value");
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {""})
  void constructorShouldRejectInvalidMappingRuleId(final String invalid) {
    assertThatThrownBy(() -> new ConfiguredMappingRule(invalid, "claim", "value"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("mappingRuleId");
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {""})
  void constructorShouldRejectInvalidClaimName(final String invalid) {
    assertThatThrownBy(() -> new ConfiguredMappingRule("rule-1", invalid, "value"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("claimName");
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {""})
  void constructorShouldRejectInvalidClaimValue(final String invalid) {
    assertThatThrownBy(() -> new ConfiguredMappingRule("rule-1", "claim", invalid))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("claimValue");
  }
}
