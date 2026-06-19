/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.port.out.AuthorizedComponentsPort;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

@ExtendWith(MockitoExtension.class)
class OidcCamundaUserServiceTest {

  @Mock CamundaAuthenticationProvider authenticationProvider;
  @Mock AuthorizedComponentsPort authorizedComponentsPort;
  @Mock OAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock HttpServletRequest request;
  @InjectMocks OidcCamundaUserService service;

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void returnsNullWhenAuthenticationAbsent() {
    when(authenticationProvider.getCamundaAuthentication()).thenReturn(null);
    assertThat(service.getCurrentUser()).isNull();
  }

  @Test
  void returnsNullWhenAuthenticationIsAnonymous() {
    when(authenticationProvider.getCamundaAuthentication())
        .thenReturn(CamundaAuthentication.anonymous());
    assertThat(service.getCurrentUser()).isNull();
  }

  @Test
  void buildsDtoFromAuthenticationWhenPresent() {
    final var authentication =
        CamundaAuthentication.of(
            b ->
                b.user("Alice")
                    .tenants(List.of("tenant-1", "tenant-2"))
                    .group("group-1")
                    .role("role-1"));
    when(authenticationProvider.getCamundaAuthentication()).thenReturn(authentication);
    when(authorizedComponentsPort.resolve(authentication)).thenReturn(List.of("operate", "admin"));

    final var dto = service.getCurrentUser();

    assertThat(dto).isNotNull();
    assertThat(dto.username()).isEqualTo("Alice");
    assertThat(dto.tenants()).containsExactly("tenant-1", "tenant-2");
    assertThat(dto.groups()).containsExactly("group-1");
    assertThat(dto.roles()).containsExactly("role-1");
    assertThat(dto.authorizedComponents()).containsExactly("operate", "admin");
    assertThat(dto.canLogout()).isTrue();
  }

  @Test
  void getUserTokenReturnsJsonStringLiteralOfAccessToken() {
    final var oidcUser =
        new DefaultOidcUser(
            List.of(),
            new OidcIdToken(
                "id-token-value",
                Instant.now(),
                Instant.now().plusSeconds(300),
                Map.of("sub", "Alice")));
    final var authToken = new OAuth2AuthenticationToken(oidcUser, List.of(), "test");
    SecurityContextHolder.setContext(new SecurityContextImpl(authToken));

    final var clientRegistration =
        ClientRegistration.withRegistrationId("test")
            .clientId("test")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost/callback")
            .authorizationUri("http://localhost/auth")
            .tokenUri("http://localhost/token")
            .build();
    final var accessToken =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            "raw-token-value",
            Instant.now(),
            Instant.now().plusSeconds(300));
    final var authorizedClient =
        new OAuth2AuthorizedClient(clientRegistration, "Alice", accessToken);
    when(authorizedClientRepository.loadAuthorizedClient(eq("test"), any(), eq(request)))
        .thenReturn(authorizedClient);

    assertThat(service.getUserToken()).isEqualTo("\"raw-token-value\"");
  }

  @Test
  void getUserTokenJsonEncodesQuotesAndBackslashes() {
    final var oidcUser =
        new DefaultOidcUser(
            List.of(),
            new OidcIdToken(
                "tok-with-\"quote\"-and-\\backslash",
                Instant.now(),
                Instant.now().plusSeconds(300),
                Map.of("sub", "Alice")));
    SecurityContextHolder.setContext(
        new SecurityContextImpl(new OAuth2AuthenticationToken(oidcUser, List.of(), "test")));

    assertThat(service.getUserToken()).isEqualTo("\"tok-with-\\\"quote\\\"-and-\\\\backslash\"");
  }

  @Test
  void getUserTokenThrowsWhenPrincipalIsNotOidcUser() {
    SecurityContextHolder.clearContext();
    assertThatThrownBy(() -> service.getUserToken())
        .isInstanceOf(UnsupportedOperationException.class)
        .hasMessageContaining("not authenticated");
  }
}
