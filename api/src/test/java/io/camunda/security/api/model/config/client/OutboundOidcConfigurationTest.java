/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.client;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class OutboundOidcConfigurationTest {

  @Test
  void scopesDefaultToEmptyList() {
    assertThat(new OutboundOidcConfiguration().getScopes()).isEmpty();
  }

  @Test
  void nullScopesGiveEmptyList() {
    final var config = new OutboundOidcConfiguration();
    config.setScopes(null);

    assertThat(config.getScopes()).isEmpty();
  }

  @Test
  void toStringDoesNotContainClientSecret() {
    final var config = new OutboundOidcConfiguration();
    config.setClientSecret("s3cr3t-value");

    assertThat(config.toString()).doesNotContain("s3cr3t-value");
  }
}
