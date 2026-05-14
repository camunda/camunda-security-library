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

class PhysicalTenantConfigurationTest {

  @Test
  void acceptsValidTenantId() {
    final var config = new PhysicalTenantConfiguration();
    config.setId("acme");
    assertThat(config.getId()).isEqualTo("acme");
  }

  @Test
  void acceptsAllowedCharacters() {
    final var config = new PhysicalTenantConfiguration();
    config.setId("acme_org-2");
    assertThat(config.getId()).isEqualTo("acme_org-2");
  }

  @Test
  void rejectsReservedDefaultId() {
    final var config = new PhysicalTenantConfiguration();
    assertThatThrownBy(() -> config.setId("default"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("reserved")
        .hasMessageContaining("camunda.security.authentication.oidc");
  }

  @Test
  void rejectsIdWithDisallowedCharacters() {
    final var config = new PhysicalTenantConfiguration();
    assertThatThrownBy(() -> config.setId("acme/globex"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid physical-tenant id");
  }

  @Test
  void rejectsEmptyId() {
    final var config = new PhysicalTenantConfiguration();
    assertThatThrownBy(() -> config.setId(""))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid physical-tenant id");
  }

  @Test
  void acceptsNullId() {
    final var config = new PhysicalTenantConfiguration();
    config.setId(null);
    assertThat(config.getId()).isNull();
  }
}
