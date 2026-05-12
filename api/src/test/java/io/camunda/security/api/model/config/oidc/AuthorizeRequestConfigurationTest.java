/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.oidc;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class AuthorizeRequestConfigurationTest {

  @Test
  void shouldRejectNullAdditionalParameters() {
    assertThatThrownBy(() -> AuthorizeRequestConfiguration.builder().additionalParameters(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("additionalParameters must not be null");
  }
}
