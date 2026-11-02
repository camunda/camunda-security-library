/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Unit tests for {@link RefreshTokenRevoker}. The request it sends, its client authentication and
 * its log redaction are covered through the logout path in {@code
 * RefreshTokenRevocationLogoutHandlerTest}; these tests cover the contract both callers rely on.
 */
class RefreshTokenRevokerTest {

  private static final String REVOCATION_ENDPOINT = "https://idp.example.com/oauth2/revoke";

  private MockRestServiceServer server;
  private RefreshTokenRevoker revoker;

  @BeforeEach
  void setUp() {
    final var restClientBuilder = RestClient.builder();
    server = MockRestServiceServer.bindTo(restClientBuilder).build();
    revoker = new RefreshTokenRevoker(null, restClientBuilder.build());
  }

  @Test
  void shouldRevokeTheRefreshTokenOfTheSuppliedClient() {
    // given
    final var registration = registration(REVOCATION_ENDPOINT);
    server
        .expect(
            request -> {
              assertThat(request.getURI()).hasToString(REVOCATION_ENDPOINT);
              assertThat(request.getMethod()).isEqualTo(HttpMethod.POST);
            })
        .andRespond(withSuccess());

    // when
    revoker.revoke(registration, () -> authorizedClient(registration));

    // then
    server.verify();
  }

  @Test
  void shouldNotReadTheClientWhenTheProviderHasNoRevocationEndpoint() {
    // given
    final var supplierCalled = new AtomicBoolean();

    // when
    revoker.revoke(
        registration(null),
        () -> {
          supplierCalled.set(true);
          return null;
        });

    // then
    assertThat(supplierCalled).isFalse();
    server.verify();
  }

  @Test
  void shouldNeverThrowWhenReadingTheClientFails() {
    // given
    final var registration = registration(REVOCATION_ENDPOINT);

    // then
    assertThatCode(
            () ->
                revoker.revoke(
                    registration,
                    () -> {
                      throw new IllegalStateException("session store unavailable");
                    }))
        .doesNotThrowAnyException();
    server.verify();
  }

  private static ClientRegistration registration(final String revocationEndpoint) {
    return ClientRegistration.withRegistrationId("oidc")
        .clientId("client-id")
        .clientSecret("client-secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://app.example.com/sso-callback")
        .authorizationUri("https://idp.example.com/oauth2/authorize")
        .tokenUri("https://idp.example.com/oauth2/token")
        .providerConfigurationMetadata(
            revocationEndpoint == null
                ? Map.of()
                : Map.of("revocation_endpoint", revocationEndpoint))
        .build();
  }

  private static OAuth2AuthorizedClient authorizedClient(final ClientRegistration registration) {
    return new OAuth2AuthorizedClient(
        registration,
        "user",
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            "access-token",
            Instant.now(),
            Instant.now().plusSeconds(60)),
        new OAuth2RefreshToken("refresh-token", Instant.now()));
  }
}
