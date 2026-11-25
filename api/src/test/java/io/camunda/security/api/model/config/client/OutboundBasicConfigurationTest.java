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

class OutboundBasicConfigurationTest {

  @Test
  void toStringDoesNotContainPassword() {
    final var config = new OutboundBasicConfiguration();
    config.setUsername("ops");
    config.setPassword("pw-XyZ123");

    assertThat(config.toString()).doesNotContain("pw-XyZ123");
  }
}
