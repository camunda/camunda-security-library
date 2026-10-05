/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.config.oidc.AuthorizeRequestConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;

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
  void shouldNotThrowOnANullRegistrationIdInTheSourcesMap() {
    // given a sources map holding a null registrationId key — not reachable from configuration
    // (Spring binds an unset/empty registration-id to "", never null), but a host handing CSL a
    // hand-built map can still produce one; the resolver's constructor must not let Map.copyOf
    // reject it and abort startup
    final var sources =
        Collections.<String, OidcConfiguration>singletonMap(null, new OidcConfiguration());

    assertThatCode(
            () ->
                new CamundaOidcAuthorizationRequestResolver(clientRegistrationRepository, sources))
        .doesNotThrowAnyException();
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

  @Test
  void shouldSendMaxAgeInWholeSecondsWhenConfigured() {
    // given
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository,
            Map.of(REGISTRATION_ID, new OidcConfiguration()),
            "/oauth2/authorization",
            Duration.ofMinutes(30));

    // when
    final var result =
        resolver.resolve(new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI));

    // then
    assertThat(result.getAdditionalParameters()).containsEntry("max_age", 1800L);
    assertThat(result.getAuthorizationRequestUri()).contains("max_age=1800");
  }

  @Test
  void shouldNotSendMaxAgeWhenNotConfigured() {
    // given
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, new OidcConfiguration()));

    // when
    final var result =
        resolver.resolve(new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI));

    // then
    assertThat(result.getAdditionalParameters()).doesNotContainKey("max_age");
  }

  @Test
  void shouldSendMaxAgeForARegistrationAbsentFromTheSourcesMap() {
    // given a registration the host added to the repository without a matching OidcConfiguration
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(), "/oauth2/authorization", Duration.ofMinutes(5));

    // when
    final var result =
        resolver.resolve(new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI));

    // then
    assertThat(result.getAdditionalParameters()).containsEntry("max_age", 300L);
  }

  @Test
  void shouldRejectNegativeMaxAge() {
    // when / then
    assertThatThrownBy(
            () ->
                new CamundaOidcAuthorizationRequestResolver(
                    clientRegistrationRepository,
                    Map.of(),
                    "/oauth2/authorization",
                    Duration.ofSeconds(-1)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("maxAge");
  }

  @Test
  void shouldSendZeroMaxAgeToForceReauthentication() {
    // given
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(), "/oauth2/authorization", Duration.ZERO);

    // when
    final var result =
        resolver.resolve(new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI));

    // then
    assertThat(result.getAdditionalParameters()).containsEntry("max_age", 0L);
  }

  @Test
  void shouldPreferAnExplicitMaxAgeAdditionalParameter() {
    // given
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var oidc = new OidcConfiguration();
    final var authorize = new AuthorizeRequestConfiguration();
    authorize.setAdditionalParameters(Map.<String, Object>of("max_age", "60"));
    oidc.setAuthorizeRequest(authorize);
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository,
            Map.of(REGISTRATION_ID, oidc),
            "/oauth2/authorization",
            Duration.ofMinutes(30));

    // when
    final var result =
        resolver.resolve(new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI));

    // then
    assertThat(result.getAdditionalParameters()).containsEntry("max_age", "60");
  }

  @Test
  void shouldSendPkceParametersForAPublicClientRegistration() {
    // given a registration built with ClientAuthenticationMethod.NONE (public client, issue #689)
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(publicClientRegistration());
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, new OidcConfiguration()));

    // when
    final var result =
        resolver.resolve(new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI));

    // then
    assertThat(result.getAttributes()).containsKey(PkceParameterNames.CODE_VERIFIER);
    assertThat(result.getAdditionalParameters())
        .containsEntry(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256")
        .containsKey(PkceParameterNames.CODE_CHALLENGE);
  }

  @Test
  void shouldNotSendPkceParametersForAConfidentialClientRegistration() {
    // given a confidential (client_secret_basic) registration that explicitly opts out of proof
    // key. Spring Security 7.1's ClientRegistration.ClientSettings defaults requireProofKey=true
    // for every authorization-code registration regardless of client-authentication-method (PKCE
    // for all, per OAuth 2.1), which would otherwise mask what this test wants to isolate: that
    // CSL's own customizer — unlike Spring's built-in one — keys PKCE only off
    // ClientAuthenticationMethod.NONE, not off ClientSettings, and so adds nothing extra for a
    // genuinely confidential client.
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(confidentialClientRegistrationWithoutProofKey());
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, new OidcConfiguration()));

    // when
    final var result =
        resolver.resolve(new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI));

    // then
    assertThat(result.getAttributes()).doesNotContainKey(PkceParameterNames.CODE_VERIFIER);
    assertThat(result.getAdditionalParameters())
        .doesNotContainKey(PkceParameterNames.CODE_CHALLENGE);
  }

  private static ClientRegistration confidentialClientRegistrationWithoutProofKey() {
    return ClientRegistration.withRegistrationId(REGISTRATION_ID)
        .clientId("test-client")
        .clientSecret("test-secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(false).build())
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("http://localhost/login/oauth2/code/" + REGISTRATION_ID)
        .scope("openid")
        .authorizationUri("http://idp.example.com/auth")
        .tokenUri("http://idp.example.com/token")
        .build();
  }

  @Test
  void shouldComposePkceWithOtherCustomizersForAPublicClientRegistration() {
    // given a public client with additional_parameters and resource also configured
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(publicClientRegistration());
    final var oidc = new OidcConfiguration();
    oidc.setResource(List.of("https://api.example.com"));
    final var authorize = new AuthorizeRequestConfiguration();
    authorize.setAdditionalParameters(Map.<String, Object>of("prompt", "consent"));
    oidc.setAuthorizeRequest(authorize);
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, oidc));

    // when
    final var result =
        resolver.resolve(new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI));

    // then
    assertThat(result.getAdditionalParameters())
        .containsEntry("prompt", "consent")
        .containsEntry("resource", List.of("https://api.example.com"))
        .containsKey(PkceParameterNames.CODE_CHALLENGE);
  }

  private static ClientRegistration publicClientRegistration() {
    return ClientRegistration.withRegistrationId(REGISTRATION_ID)
        .clientId("test-public-client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("http://localhost/login/oauth2/code/" + REGISTRATION_ID)
        .scope("openid")
        .authorizationUri("http://idp.example.com/auth")
        .tokenUri("http://idp.example.com/token")
        .build();
  }

  @Test
  void shouldLetConcurrentRequestsResolveTheSameRegistrationAtTheSameTime() throws Exception {
    // given
    final var bothInside = new CountDownLatch(2);
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenAnswer(
            invocation -> {
              bothInside.countDown();
              assertThat(bothInside.await(5, TimeUnit.SECONDS)).isTrue();
              return clientRegistration;
            });
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, new OidcConfiguration()));
    final var executor = Executors.newFixedThreadPool(2);

    try {
      // when
      final var requests =
          List.of(
              executor.submit(
                  () ->
                      resolver.resolve(
                          new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI))),
              executor.submit(
                  () ->
                      resolver.resolve(
                          new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI))));

      // then
      for (final var request : requests) {
        assertThat(request.get(10, TimeUnit.SECONDS)).isNotNull();
      }
    } finally {
      executor.shutdownNow();
    }
  }
}
