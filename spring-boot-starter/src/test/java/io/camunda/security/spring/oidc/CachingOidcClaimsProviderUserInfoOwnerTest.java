/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Whether a token is augmented from UserInfo is decided by the provider it is routed to, also when
 * another provider's issuer differs from it only by a trailing slash.
 */
class CachingOidcClaimsProviderUserInfoOwnerTest {

  private static final String USER_INFO_URI = "https://idp/with-user-info/userinfo";

  /**
   * The provider at https://idp has UserInfo disabled, its twin at https://idp/ has it enabled. A
   * token routed exactly to https://idp passes through unaugmented, rather than failing because the
   * disabled provider exposes no UserInfo endpoint.
   */
  @Test
  void shouldNotAugmentATokenOfAProviderWithUserInfoDisabledFromItsLookAlikeTwin() {
    // given
    final var userInfoUriByIssuer = userInfoUriByIssuerForTwins();

    // when / then
    assertThat(userInfoUriByIssuer.apply("https://idp")).isNull();
  }

  @Test
  void shouldAugmentATokenOfTheProviderWithUserInfoEnabled() {
    // given
    final var userInfoUriByIssuer = userInfoUriByIssuerForTwins();

    // when / then
    assertThat(userInfoUriByIssuer.apply("https://idp/")).isEqualTo(USER_INFO_URI);
  }

  private static java.util.function.Function<String, String> userInfoUriByIssuerForTwins() {
    final var providers =
        Map.of(
            "without-user-info",
                OidcConfiguration.builder().issuerUri("https://idp").userInfoEnabled(false).build(),
            "with-user-info",
                OidcConfiguration.builder()
                    .issuerUri("https://idp/")
                    .userInfoEnabled(true)
                    .build());
    final var withoutUserInfo = registration("without-user-info", "https://idp", null);
    final var withUserInfo = registration("with-user-info", "https://idp/", USER_INFO_URI);
    final var registrations =
        IssuerRegistrations.ofConfiguration(
            providers, id -> "with-user-info".equals(id) ? withUserInfo : withoutUserInfo);
    return CachingOidcClaimsProvider.userInfoUriByIssuer(registrations, providers);
  }

  private static ClientRegistration registration(
      final String registrationId, final String issuer, final String userInfoUri) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/cb")
        .authorizationUri("https://idp/" + registrationId + "/auth")
        .tokenUri("https://idp/" + registrationId + "/token")
        .jwkSetUri("https://idp/" + registrationId + "/jwks")
        .userInfoUri(userInfoUri)
        .issuerUri(issuer)
        .build();
  }
}
