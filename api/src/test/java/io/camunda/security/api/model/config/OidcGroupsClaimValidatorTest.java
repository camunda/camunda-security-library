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

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.validator.OidcGroupsClaimValidator;
import org.junit.jupiter.api.Test;

class OidcGroupsClaimValidatorTest {

  @Test
  void shouldSanitizePlainClaimToJsonPath() {
    assertThat(OidcGroupsClaimValidator.sanitizeClaimPath("groups")).isEqualTo("$['groups']");
  }

  @Test
  void shouldKeepJsonPathClaimAsIs() {
    assertThat(OidcGroupsClaimValidator.sanitizeClaimPath("$.realm.groups"))
        .isEqualTo("$.realm.groups");
  }

  @Test
  void shouldRejectPlainClaimWithSingleQuote() {
    assertThatThrownBy(() -> OidcGroupsClaimValidator.validate("groups'claim"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldBeUsedByOidcConfigurationSetterAndBuilder() {
    final OidcConfiguration configuration = new OidcConfiguration();

    assertThatThrownBy(() -> configuration.setGroupsClaim("groups'claim"))
        .isInstanceOf(IllegalArgumentException.class);

    assertThatThrownBy(() -> OidcConfiguration.builder().groupsClaim("groups'claim"))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
