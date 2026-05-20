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
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.config.oidc.AuthorizeRequestConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Unit tests for {@link CamundaOidcAuthorizationRequestResolver}. The resolver lifts OC's
 * per-registration customizer logic into CSL: it adds {@code additional_parameters} and {@code
 * resource} (RFC 8707) to the OAuth2 authorization request when configured on the matching {@link
 * OidcConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class CamundaOidcAuthorizationRequestResolverTest {

  private static final String REGISTRATION_ID = "test-oidc";
  private static final String AUTHORIZATION_REQUEST_URI =
      "/oauth2/authorization/" + REGISTRATION_ID;

  @Mock private ClientRegistrationRepository clientRegistrationRepository;

  private ClientRegistration clientRegistration;

  @BeforeEach
  void setUp() {
    clientRegistration =
        ClientRegistration.withRegistrationId(REGISTRATION_ID)
            .clientId("test-client")
            .clientSecret("test-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost/login/oauth2/code/" + REGISTRATION_ID)
            .scope("openid")
            .authorizationUri("http://idp.example.com/auth")
            .tokenUri("http://idp.example.com/token")
            .build();
  }

  @Test
  void shouldReturnNullWhenPathDoesNotMatchAuthorizationRequestBaseUri() {
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, new OidcConfiguration()));
    final var request = new MockHttpServletRequest("GET", "/some/other/path");

    assertThat(resolver.resolve(request)).isNull();
  }

  @Test
  void shouldReturnNullWhenRegistrationIdArgIsBlank() {
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, new OidcConfiguration()));
    final var request = new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI);

    assertThat(resolver.resolve(request, "")).isNull();
    assertThat(resolver.resolve(request, null)).isNull();
  }

  @Test
  void shouldThrowWhenRegistrationIdIsUnknownToTheRepository() {
    when(clientRegistrationRepository.findByRegistrationId("missing")).thenReturn(null);

    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, new OidcConfiguration()));
    final var request = new MockHttpServletRequest("GET", "/oauth2/authorization/missing");

    assertThatThrownBy(() -> resolver.resolve(request))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid Client Registration with ID 'missing'");
  }

  @Test
  void shouldProduceUncustomizedRequestWhenNoCustomizationsConfigured() {
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, new OidcConfiguration()));
    final var request = new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI);

    final var result = resolver.resolve(request);

    assertThat(result).isNotNull();
    assertThat(result.getAdditionalParameters()).doesNotContainKey("resource");
  }

  @Test
  void shouldAddEveryAdditionalParameterWhenConfigured() {
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var oidc = new OidcConfiguration();
    final var authorize = new AuthorizeRequestConfiguration();
    authorize.setAdditionalParameters(
        Map.<String, Object>of("prompt", "consent", "audience", "api"));
    oidc.setAuthorizeRequest(authorize);

    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, oidc));
    final var request = new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI);

    final var result = resolver.resolve(request);

    assertThat(result.getAdditionalParameters())
        .containsEntry("prompt", "consent")
        .containsEntry("audience", "api");
  }

  @Test
  void shouldAddResourceParameterWhenConfigured() {
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var oidc = new OidcConfiguration();
    oidc.setResource(List.of("https://api.example.com"));

    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, oidc));
    final var request = new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI);

    final var result = resolver.resolve(request);

    assertThat(result.getAdditionalParameters())
        .containsEntry("resource", List.of("https://api.example.com"));
  }

  @Test
  void shouldAddBothAdditionalParametersAndResourceWhenBothConfigured() {
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var oidc = new OidcConfiguration();
    oidc.setResource(List.of("https://api.example.com"));
    final var authorize = new AuthorizeRequestConfiguration();
    authorize.setAdditionalParameters(Map.<String, Object>of("prompt", "consent"));
    oidc.setAuthorizeRequest(authorize);

    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, oidc));
    final var request = new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI);

    final var result = resolver.resolve(request);

    assertThat(result.getAdditionalParameters())
        .containsEntry("prompt", "consent")
        .containsEntry("resource", List.of("https://api.example.com"));
  }
}
