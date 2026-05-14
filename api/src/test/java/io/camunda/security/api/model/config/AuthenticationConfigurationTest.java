/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuthenticationConfigurationTest {

  @Test
  void shouldEnableCamundaGroupsAndUsersInBasicAuth() {
    // given:
    final var config = new AuthenticationConfiguration();
    config.setMethod(AuthenticationMethod.BASIC);

    // expect:
    assertThat(config.isCamundaUsersEnabled()).isTrue();
    assertThat(config.isCamundaGroupsEnabled()).isTrue();
  }

  @Test
  void shouldEnableOnlyCamundaGroupsInOIDCAuth() {
    // given:
    final var config = new AuthenticationConfiguration();
    config.setMethod(AuthenticationMethod.OIDC);

    // expect:
    assertThat(config.isCamundaUsersEnabled()).isFalse();
    assertThat(config.isCamundaGroupsEnabled()).isTrue();
  }

  @Test
  void shouldDisableCamundaGroupsAndUsersInOIDCAuthWithGroupsClaim() {
    // given:
    final var config = new AuthenticationConfiguration();
    config.setMethod(AuthenticationMethod.OIDC);
    config.getOidc().setGroupsClaim("groups");

    // expect:
    assertThat(config.isCamundaUsersEnabled()).isFalse();
    assertThat(config.isCamundaGroupsEnabled()).isFalse();
  }

  @Test
  void shouldEnableCamundaGroupsWhenOidcGroupsClaimIsNotConfigured() {
    // given:
    final var config = new AuthenticationConfiguration();
    config.setMethod(AuthenticationMethod.OIDC);
    config.setOidc(null);

    // expect: setOidc(null) is normalised to a fresh OidcConfiguration; with no groups claim
    // configured, Camunda-managed groups remain enabled.
    assertThat(config.getOidc()).isNotNull();
    assertThat(config.isCamundaUsersEnabled()).isFalse();
    assertThat(config.isCamundaGroupsEnabled()).isTrue();
  }
}
