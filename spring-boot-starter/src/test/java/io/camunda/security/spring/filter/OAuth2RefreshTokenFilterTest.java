/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import jakarta.servlet.FilterChain;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@ExtendWith(MockitoExtension.class)
class OAuth2RefreshTokenFilterTest {

  private static final String REGISTRATION_ID = "registration-id";

  @Mock private OAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock private OAuth2AuthorizedClientManager authorizedClientManager;
  @Mock private LogoutHandler logoutHandler;
  @Mock private FilterChain chain;

  @Test
  void shouldLogWarnAndConvertToControlledLogoutWhenRefreshFailsWithInvalidGrant()
      throws Exception {
    // given - an expired access token with a refresh token, whose refresh attempt fails because
    // the refresh token itself is no longer valid (invalid_grant), as reported by the IdP
    final OAuth2AuthenticationToken authenticationToken = authenticationToken();
    final OAuth2AuthorizedClient authorizedClient = expiredAuthorizedClientWithRefreshToken();
    when(authorizedClientRepository.loadAuthorizedClient(
            eq(REGISTRATION_ID), eq(authenticationToken), any()))
        .thenReturn(authorizedClient);
    // DefaultOAuth2AuthorizedClientManager#authorize rethrows the provider's
    // OAuth2AuthorizationException as-is on a failed refresh
    when(authorizedClientManager.authorize(any()))
        .thenThrow(
            new ClientAuthorizationException(
                new OAuth2Error("invalid_grant"), REGISTRATION_ID, "Token is not active"));
    final var filter =
        new OAuth2RefreshTokenFilter(
            authorizedClientRepository,
            authorizedClientManager,
            logoutHandler,
            securityContextSupplier(authenticationToken));

    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();

    final ListAppender<ILoggingEvent> appender = attachAppender();
    try {
      // when / then - the raw ClientAuthorizationException must not escape the filter: it is
      // caught and converted to the controlled OAuth2AuthenticationException + logout flow
      assertThatThrownBy(() -> filter.doFilter(request, response, chain))
          .isInstanceOf(OAuth2AuthenticationException.class)
          .isNotInstanceOf(ClientAuthorizationException.class);
    } finally {
      detachAppender(appender);
    }

    verify(logoutHandler).logout(eq(request), eq(response), eq(authenticationToken));
    verify(chain, never()).doFilter(any(), any());
    assertThat(appender.list)
        .anySatisfy(
            event -> {
              assertThat(event.getLevel()).isEqualTo(Level.WARN);
              assertThat(event.getFormattedMessage()).contains("Failed to refresh access token");
            });
  }

  private static OAuth2AuthenticationToken authenticationToken() {
    final OAuth2User principal =
        new DefaultOAuth2User(
            List.of(new SimpleGrantedAuthority("ROLE_USER")), Map.of("sub", "user-1"), "sub");
    return new OAuth2AuthenticationToken(principal, principal.getAuthorities(), REGISTRATION_ID);
  }

  private static OAuth2AuthorizedClient expiredAuthorizedClientWithRefreshToken() {
    final ClientRegistration clientRegistration =
        ClientRegistration.withRegistrationId(REGISTRATION_ID)
            .clientId("client-id")
            .clientSecret("secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("https://idp.example.com/authorize")
            .tokenUri("https://idp.example.com/token")
            .build();
    final OAuth2AccessToken expiredAccessToken =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            "expired-token",
            Instant.now().minusSeconds(120),
            Instant.now().minusSeconds(60));
    final OAuth2RefreshToken refreshToken =
        new OAuth2RefreshToken("refresh-token", Instant.now().minusSeconds(120));
    return new OAuth2AuthorizedClient(
        clientRegistration, "user-1", expiredAccessToken, refreshToken);
  }

  private static Supplier<SecurityContext> securityContextSupplier(
      final OAuth2AuthenticationToken authenticationToken) {
    final SecurityContext securityContext = new SecurityContextImpl(authenticationToken);
    return () -> securityContext;
  }

  private static ListAppender<ILoggingEvent> attachAppender() {
    final Logger logger = (Logger) LoggerFactory.getLogger(OAuth2RefreshTokenFilter.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachAppender(final ListAppender<ILoggingEvent> appender) {
    final Logger logger = (Logger) LoggerFactory.getLogger(OAuth2RefreshTokenFilter.class);
    logger.detachAppender(appender);
  }
}
