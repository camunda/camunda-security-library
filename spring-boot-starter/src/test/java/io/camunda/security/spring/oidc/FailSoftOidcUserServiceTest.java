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

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

class FailSoftOidcUserServiceTest {

  private static ClientRegistration.Builder registrationBuilder() {
    return ClientRegistration.withRegistrationId("test-idp")
        .clientId("client")
        .clientSecret("secret")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp.example.com/auth")
        .tokenUri("https://idp.example.com/token")
        .userInfoUri("https://idp.example.com/userinfo")
        .userNameAttributeName("sub")
        .jwkSetUri("https://idp.example.com/jwks");
  }

  private static OidcUserRequest requestFor(final ClientRegistration registration) {
    final var now = Instant.now();
    final var idToken =
        new OidcIdToken("id-token-value", now, now.plusSeconds(300), Map.of("sub", "alice"));
    final var accessToken =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER, "access-token-value", now, now.plusSeconds(300));
    return new OidcUserRequest(registration, accessToken, idToken);
  }

  private static OAuth2AuthenticationException transportFailure() {
    final var error = new OAuth2Error("invalid_user_info_response", "401 from /userinfo", null);
    return new OAuth2AuthenticationException(error, error.toString());
  }

  @Test
  void loadsUserNormallyWhenUserInfoFetchSucceeds() {
    final OAuth2UserService<OAuth2UserRequest, OAuth2User> fetcher =
        request -> new DefaultOAuth2User(java.util.List.of(), Map.of("sub", "alice"), "sub");
    final var service = new FailSoftOidcUserService(fetcher);
    final var request = requestFor(registrationBuilder().build());

    final var result = service.loadUser(request);

    assertThat(result.getUserInfo()).isNotNull();
    assertThat(result.getName()).isEqualTo("alice");
  }

  @Test
  void fallsBackToIdTokenOnlyClaimsWhenFetchFailsAndUserInfoNotRequired() {
    final var fetchCount = new java.util.concurrent.atomic.AtomicInteger();
    final OAuth2UserService<OAuth2UserRequest, OAuth2User> fetcher =
        request -> {
          fetchCount.incrementAndGet();
          throw transportFailure();
        };
    final var service = new FailSoftOidcUserService(fetcher);
    final var request = requestFor(registrationBuilder().build());

    final var result = service.loadUser(request);

    assertThat(result.getUserInfo()).isNull();
    assertThat(result.getIdToken().getTokenValue()).isEqualTo("id-token-value");
    assertThat(result.getName()).isEqualTo("alice");
    // Pins that the fallback never retries the failed delegate — it takes Spring's own
    // retrieveUserInfo=false branch instead, via a second, independent OidcUserService.
    assertThat(fetchCount).hasValue(1);
  }

  @Test
  void defaultsToFailSoftWhenRegistrationCarriesNoCslMetadata() {
    // Simulates a host-replaced ClientRegistrationRepository built without
    // ScopedClientRegistrationFactory: no USER_INFO_REQUIRED_METADATA_KEY entry at all.
    final OAuth2UserService<OAuth2UserRequest, OAuth2User> fetcher =
        request -> {
          throw transportFailure();
        };
    final var service = new FailSoftOidcUserService(fetcher);
    final var registration = registrationBuilder().build();
    assertThat(
            registration
                .getProviderDetails()
                .getConfigurationMetadata()
                .containsKey(FailSoftOidcUserService.USER_INFO_REQUIRED_METADATA_KEY))
        .isFalse();

    final var result = service.loadUser(requestFor(registration));

    assertThat(result.getUserInfo()).isNull();
  }

  @Test
  void rethrowsWhenUserInfoRequiredAndFetchFails() {
    final var originalFailure = transportFailure();
    final OAuth2UserService<OAuth2UserRequest, OAuth2User> fetcher =
        request -> {
          throw originalFailure;
        };
    final var service = new FailSoftOidcUserService(fetcher);
    final var registration =
        ClientRegistration.withClientRegistration(registrationBuilder().build())
            .providerConfigurationMetadata(
                Map.of(FailSoftOidcUserService.USER_INFO_REQUIRED_METADATA_KEY, true))
            .build();

    // Rethrows the literal original exception, not the private wrapping marker — the marker is
    // an internal control-flow signal and must never escape loadUser().
    assertThatThrownBy(() -> service.loadUser(requestFor(registration))).isSameAs(originalFailure);
  }

  @Test
  void stillThrowsOnSubMismatchRegardlessOfUserInfoRequired() {
    // The fetch itself succeeds; OidcUserService's own OIDC S:5.3.2 sub-check then fails. This
    // must propagate even though user-info-required is false (the default) — the acceptance
    // criterion this test pins.
    final OAuth2UserService<OAuth2UserRequest, OAuth2User> fetcher =
        request -> new DefaultOAuth2User(java.util.List.of(), Map.of("sub", "someone-else"), "sub");
    final var service = new FailSoftOidcUserService(fetcher);
    final var request = requestFor(registrationBuilder().build());

    assertThatThrownBy(() -> service.loadUser(request))
        .isInstanceOf(OAuth2AuthenticationException.class)
        .satisfies(
            ex ->
                assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                    .isEqualTo("invalid_user_info_response"));
  }
}
