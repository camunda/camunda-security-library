/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ConfigurationRecordsTest {

  @Test
  void basicRejectsAUsernameWithAColon() {
    assertThatThrownBy(() -> new BasicAuthConfiguration("a:b", "pw"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("username must not contain ':'");
  }

  @Test
  void basicValidatesAndMasksThePassword() {
    assertThatThrownBy(() -> new BasicAuthConfiguration("", "pw"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("username");
    assertThatThrownBy(() -> new BasicAuthConfiguration("u", null))
        .isInstanceOf(NullPointerException.class);

    assertThat(new BasicAuthConfiguration("u", "pw-secret").toString())
        .doesNotContain("pw-secret")
        .contains("username=u", "password=***");
  }

  @Test
  void basicEqualsAndHashCodeFollowAllValues() {
    final var config = new BasicAuthConfiguration("u", "pw");

    assertThat(config)
        .isEqualTo(new BasicAuthConfiguration("u", "pw"))
        .hasSameHashCodeAs(new BasicAuthConfiguration("u", "pw"))
        .isNotEqualTo(new BasicAuthConfiguration("other", "pw"))
        .isNotEqualTo(new BasicAuthConfiguration("u", "other"))
        .isNotEqualTo(null)
        .isNotEqualTo("u");
  }
}
