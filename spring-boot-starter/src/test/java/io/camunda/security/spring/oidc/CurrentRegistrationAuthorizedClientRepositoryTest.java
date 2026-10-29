/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

@ExtendWith(MockitoExtension.class)
class CurrentRegistrationAuthorizedClientRepositoryTest {

  @Mock private OAuth2AuthorizedClientRepository delegate;
  @Mock private ClientRegistrationRepository registrations;
  @Mock private Authentication principal;

  @Test
  void shouldBindAStoredClientToTheCurrentRegistration() {
    // given
    final var stored = client(registration("old-secret"));
    final var current = registration("new-secret");
    final var request = new MockHttpServletRequest();
    when(delegate.loadAuthorizedClient("app", principal, request)).thenReturn(stored);
    when(registrations.findByRegistrationId("app")).thenReturn(current);

    // when
    final OAuth2AuthorizedClient loaded =
        new CurrentRegistrationAuthorizedClientRepository(delegate, registrations)
            .loadAuthorizedClient("app", principal, request);

    // then
    assertThat(loaded.getClientRegistration()).isSameAs(current);
    assertThat(loaded.getAccessToken()).isSameAs(stored.getAccessToken());
    assertThat(loaded.getRefreshToken()).isSameAs(stored.getRefreshToken());
    assertThat(loaded.getPrincipalName()).isEqualTo("alice");
  }

  @Test
  void shouldReturnTheStoredClientWhenItsRegistrationIsCurrent() {
    // given
    final var current = registration("secret");
    final var stored = client(current);
    final var request = new MockHttpServletRequest();
    when(delegate.loadAuthorizedClient("app", principal, request)).thenReturn(stored);
    when(registrations.findByRegistrationId("app")).thenReturn(current);

    // when
    final OAuth2AuthorizedClient loaded =
        new CurrentRegistrationAuthorizedClientRepository(delegate, registrations)
            .loadAuthorizedClient("app", principal, request);

    // then
    assertThat(loaded).isSameAs(stored);
  }

  @Test
  void shouldReportAClientWhoseRegistrationTheScopeDroppedAsAbsent() {
    // given
    final var request = new MockHttpServletRequest();
    when(delegate.loadAuthorizedClient("app", principal, request))
        .thenReturn(client(registration("secret")));

    // when
    final OAuth2AuthorizedClient loaded =
        new CurrentRegistrationAuthorizedClientRepository(delegate, registrations)
            .loadAuthorizedClient("app", principal, request);

    // then
    assertThat(loaded).isNull();
  }

  @Test
  void shouldStoreAndRemoveThroughTheDelegate() {
    // given
    final var repository =
        new CurrentRegistrationAuthorizedClientRepository(delegate, registrations);
    final var client = client(registration("secret"));
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();

    // when
    repository.saveAuthorizedClient(client, principal, request, response);
    repository.removeAuthorizedClient("app", principal, request, response);

    // then
    verify(delegate).saveAuthorizedClient(client, principal, request, response);
    verify(delegate).removeAuthorizedClient(eq("app"), eq(principal), any(), any());
  }

  private static ClientRegistration registration(final String secret) {
    return ClientRegistration.withRegistrationId("app")
        .clientId("app")
        .clientSecret(secret)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp/auth")
        .tokenUri("https://idp/token")
        .build();
  }

  private static OAuth2AuthorizedClient client(final ClientRegistration registration) {
    final var now = Instant.now();
    return new OAuth2AuthorizedClient(
        registration,
        "alice",
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER, "access", now, now.plusSeconds(60)),
        new OAuth2RefreshToken("refresh", now));
  }
}
