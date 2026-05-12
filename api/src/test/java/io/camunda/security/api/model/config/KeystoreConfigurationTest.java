/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class KeystoreConfigurationTest {

  @Test
  void shouldRequireConfiguredPathBeforeLoadingKeystore() {
    final var configuration = KeystoreConfiguration.builder().password("secret").build();

    assertThatThrownBy(configuration::loadKeystore)
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("Keystore path must be configured");
  }

  @Test
  void shouldRequireConfiguredPasswordBeforeLoadingKeystore() {
    final var configuration =
        KeystoreConfiguration.builder().path("/tmp/test-keystore.p12").build();

    assertThatThrownBy(configuration::loadKeystore)
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("Keystore password must be configured");
  }
}
