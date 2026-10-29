/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

@ExtendWith(MockitoExtension.class)
class DefaultOAuth2AuthorizedClientManagerFactoryTest {

  @Mock private OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshClient;

  @Test
  void shouldRefreshThroughTheScopesTokenResponseClient() {
    // given
    final var registration =
        ClientRegistration.withRegistrationId("app")
            .clientId("app")
            .clientSecret("secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/sso-callback")
            .authorizationUri("https://idp/auth")
            .tokenUri("https://idp/token")
            .build();
    final var manager =
        new DefaultOAuth2AuthorizedClientManagerFactory()
            .create(
                new InMemoryClientRegistrationRepository(registration),
                new HttpSessionOAuth2AuthorizedClientRepository(),
                refreshClient);
    final var expired = Instant.now().minusSeconds(600);
    final var client =
        new OAuth2AuthorizedClient(
            registration,
            "alice",
            new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "old", expired.minusSeconds(60), expired),
            new OAuth2RefreshToken("refresh", expired.minusSeconds(60)));
    when(refreshClient.getTokenResponse(any()))
        .thenReturn(
            OAuth2AccessTokenResponse.withToken("new")
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(300)
                .build());

    // when
    final var refreshed =
        manager.authorize(
            OAuth2AuthorizeRequest.withAuthorizedClient(client)
                .principal(new TestingAuthenticationToken("alice", null))
                .attribute(
                    jakarta.servlet.http.HttpServletRequest.class.getName(),
                    new MockHttpServletRequest())
                .attribute(
                    jakarta.servlet.http.HttpServletResponse.class.getName(),
                    new MockHttpServletResponse())
                .build());

    // then
    verify(refreshClient).getTokenResponse(any());
    assertThat(refreshed.getAccessToken().getTokenValue()).isEqualTo("new");
  }
}
