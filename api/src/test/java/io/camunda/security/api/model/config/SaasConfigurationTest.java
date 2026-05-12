/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class SaasConfigurationTest {

  @Test
  void shouldBeConfiguredWhenOrganizationAndClusterIdsAreSet() {
    final var configuration = new SaasConfiguration();
    configuration.setOrganizationId("organization");
    configuration.setClusterId("cluster");

    assertThat(configuration.isConfigured()).isTrue();
  }

  @Test
  void shouldNotBeConfiguredWhenOrganizationAndClusterIdsAreBlank() {
    final var configuration = new SaasConfiguration();
    configuration.setOrganizationId(" ");
    configuration.setClusterId("");

    assertThat(configuration.isConfigured()).isFalse();
  }

  @Test
  void shouldThrowWhenOnlyOrganizationIdIsConfigured() {
    final var configuration = new SaasConfiguration();
    configuration.setOrganizationId("organization");

    assertThatThrownBy(configuration::isConfigured)
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("Must configure both organizationId and clusterId");
  }

  @Test
  void shouldThrowWhenOnlyClusterIdIsConfigured() {
    final var configuration = new SaasConfiguration();
    configuration.setOrganizationId(" ");
    configuration.setClusterId("cluster");

    assertThatThrownBy(configuration::isConfigured)
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("Must configure both organizationId and clusterId");
  }
}
