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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Whether a token is augmented from UserInfo is decided by the provider that owns its issuer. Two
 * issuers that differ only by a trailing slash are one issuer, owned by the provider declared
 * first.
 */
class CachingOidcClaimsProviderUserInfoOwnerTest {

  private static final String USER_INFO_URI = "https://idp/with-user-info/userinfo";

  /**
   * The owner has UserInfo disabled, its twin has it enabled. Tokens of either form pass through
   * unaugmented, rather than borrowing the twin's endpoint or failing on the owner's missing one.
   */
  @ParameterizedTest
  @ValueSource(strings = {"https://idp", "https://idp/"})
  void shouldNotAugmentWhenTheOwnerOfATwinIssuerHasUserInfoDisabled(final String tokenIssuer) {
    // given
    final var userInfoUriByIssuer = userInfoUriByIssuer(false);

    // when / then
    assertThat(userInfoUriByIssuer.apply(tokenIssuer)).isNull();
  }

  @ParameterizedTest
  @ValueSource(strings = {"https://idp", "https://idp/"})
  void shouldAugmentWhenTheOwnerOfATwinIssuerHasUserInfoEnabled(final String tokenIssuer) {
    // given
    final var userInfoUriByIssuer = userInfoUriByIssuer(true);

    // when / then
    assertThat(userInfoUriByIssuer.apply(tokenIssuer)).isEqualTo(USER_INFO_URI);
  }

  /**
   * @param withUserInfoFirst whether the provider with UserInfo enabled is declared first, and so
   *     owns both forms of the issuer
   */
  private static Function<String, String> userInfoUriByIssuer(final boolean withUserInfoFirst) {
    final var without =
        OidcConfiguration.builder().issuerUri("https://idp").userInfoEnabled(false).build();
    final var with =
        OidcConfiguration.builder().issuerUri("https://idp/").userInfoEnabled(true).build();
    final Map<String, OidcConfiguration> providers = new LinkedHashMap<>();
    if (withUserInfoFirst) {
      providers.put("with-user-info", with);
      providers.put("without-user-info", without);
    } else {
      providers.put("without-user-info", without);
      providers.put("with-user-info", with);
    }
    // An unrelated provider with UserInfo, so augmentation stays configured when the twin's owner
    // has it disabled: otherwise no owner yields an endpoint, and the setup is rejected at start.
    providers.put(
        "unrelated",
        OidcConfiguration.builder().issuerUri("https://unrelated").userInfoEnabled(true).build());
    final var withoutUserInfo = registration("without-user-info", null);
    final var withUserInfo = registration("with-user-info", USER_INFO_URI);
    final var registrations =
        IssuerRegistrations.ofConfiguration(
            providers,
            id ->
                switch (id) {
                  case "with-user-info" -> withUserInfo;
                  case "without-user-info" -> withoutUserInfo;
                  default -> throw new AssertionError("not resolved in these tests: " + id);
                });
    return CachingOidcClaimsProvider.userInfoUriByIssuer(registrations, providers);
  }

  /** Both registrations resolved to the provider's issuer. */
  private static ClientRegistration registration(
      final String registrationId, final String userInfoUri) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/cb")
        .authorizationUri("https://idp/" + registrationId + "/auth")
        .tokenUri("https://idp/" + registrationId + "/token")
        .jwkSetUri("https://idp/" + registrationId + "/jwks")
        .userInfoUri(userInfoUri)
        .issuerUri("https://idp")
        .build();
  }
}
