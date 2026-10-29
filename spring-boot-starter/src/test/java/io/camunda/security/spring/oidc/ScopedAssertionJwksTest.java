/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.config.AssertionConfiguration;
import io.camunda.security.api.model.config.KeystoreConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class ScopedAssertionJwksTest {

  @Test
  void shouldReadTheKeyOfTheScopesOwnRegistrationOnce() throws Exception {
    // given
    final var jwks =
        new ScopedAssertionJwks(Map.of("app", provider("keystore.p12", "camunda-standalone")));

    // when
    final var first = jwks.apply(registration("app"));
    final var second = jwks.apply(registration("app"));

    // then
    assertThat(first.isPrivate()).isTrue();
    assertThat(second).isSameAs(first);
    assertThat(jwks.resolvedCount()).isOne();
  }

  @Test
  void shouldReadTheKeyAgainInANewInstance() throws Exception {
    // given
    final var providers = Map.of("app", provider("keystore.p12", "camunda-standalone"));

    // when
    final var first = new ScopedAssertionJwks(providers).apply(registration("app"));
    final var second = new ScopedAssertionJwks(providers).apply(registration("app"));

    // then
    assertThat(second).isNotSameAs(first).isEqualTo(first);
  }

  @Test
  void shouldNotResolveARegistrationOfAnotherScope() throws Exception {
    // given
    final var jwks =
        new ScopedAssertionJwks(Map.of("app", provider("keystore.p12", "camunda-standalone")));

    // when / then
    assertThatThrownBy(() -> jwks.apply(registration("other")))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private static OidcConfiguration provider(final String keystore, final String alias)
      throws Exception {
    final var path =
        Paths.get(
                Objects.requireNonNull(
                        ScopedAssertionJwksTest.class.getClassLoader().getResource(keystore))
                    .toURI())
            .toString();
    return OidcConfiguration.builder()
        .clientId("app")
        .assertionConfiguration(
            AssertionConfiguration.builder()
                .keystoreConfiguration(
                    KeystoreConfiguration.builder()
                        .path(path)
                        .password("password")
                        .keyAlias(alias)
                        .keyPassword("password")
                        .build())
                .build())
        .build();
  }

  private static ClientRegistration registration(final String registrationId) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("app")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp/auth")
        .tokenUri("https://idp/token")
        .build();
  }
}
