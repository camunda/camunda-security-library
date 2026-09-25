/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.oidc.OidcAccessTokenDecoderFactory;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

@ExtendWith(MockitoExtension.class)
class OidcUserAuthenticationConverterTest {

  @Mock private OAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock private JwtDecoder jwtDecoder;
  @Mock private LazyTokenClaimsConverter tokenClaimsConverter;
  @Mock private HttpServletRequest request;
  @Mock private OidcAccessTokenDecoderFactory oidcAccessTokenDecoderFactory;
  @InjectMocks private OidcUserAuthenticationConverter converter;

  @BeforeEach
  void setUp() {
    // lenient: not all tests reach the decoder factory. The first matcher is typed to
    // ClientRegistration to bind the createAccessTokenDecoder(ClientRegistration, List<String>)
    // overload explicitly and keep the stub readable.
    lenient()
        .when(
            oidcAccessTokenDecoderFactory.createAccessTokenDecoder(
                any(ClientRegistration.class), any()))
        .thenReturn(jwtDecoder);
  }

  @Test
  void shouldSupportOAuth2AuthenticationToken() {
    assertThat(converter.supports(mock(OAuth2AuthenticationToken.class))).isTrue();
  }

  @Test
  void shouldNotSupportJwtAuthenticationToken() {
    assertThat(converter.supports(mock(JwtAuthenticationToken.class))).isFalse();
  }

  @Test
  void shouldUseAccessTokenClaimsWhenAvailable() {
    final var token = mockAuthToken("oidc");
    final var registration = mockRegistration("oidc");
    final var accessToken = mock(OAuth2AccessToken.class);
    when(accessToken.getTokenValue()).thenReturn("at");
    final var client = mock(OAuth2AuthorizedClient.class);
    when(client.getAccessToken()).thenReturn(accessToken);
    when(client.getClientRegistration()).thenReturn(registration);
    when(authorizedClientRepository.loadAuthorizedClient("oidc", token, request))
        .thenReturn(client);

    final Map<String, Object> claims = Map.of("sub", "alice");
    final var jwt =
        Jwt.withTokenValue("at").header("alg", "RS256").claims(c -> c.putAll(claims)).build();
    when(jwtDecoder.decode("at")).thenReturn(jwt);

    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(jwt.getClaims())).thenReturn(expected);

    assertThat(converter.convert(token)).isSameAs(expected);
  }

  @Test
  void shouldFallBackToIdTokenClaimsWhenAccessTokenAbsent() {
    final var token = mockAuthToken("oidc");
    when(authorizedClientRepository.loadAuthorizedClient("oidc", token, request)).thenReturn(null);

    final var oidcUser = mock(OidcUser.class);
    when(token.getPrincipal()).thenReturn(oidcUser);
    final Map<String, Object> idClaims = Map.of("sub", "alice", "source", "id-token");
    when(oidcUser.getAttributes()).thenReturn(idClaims);

    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(idClaims)).thenReturn(expected);

    assertThat(converter.convert(token)).isSameAs(expected);
    verify(jwtDecoder, never()).decode(any());
  }

  @Test
  void shouldWrapIllegalArgumentExceptionAsOAuth2AuthenticationException() {
    final var token = mockAuthToken("oidc");
    when(authorizedClientRepository.loadAuthorizedClient("oidc", token, request)).thenReturn(null);
    final var oidcUser = mock(OidcUser.class);
    when(token.getPrincipal()).thenReturn(oidcUser);
    when(oidcUser.getAttributes()).thenReturn(Map.of("sub", "alice"));
    when(tokenClaimsConverter.convert(any())).thenThrow(new IllegalArgumentException("bad token"));

    assertThatThrownBy(() -> converter.convert(token))
        .isInstanceOf(OAuth2AuthenticationException.class)
        .hasMessageContaining("bad token");
  }

  @Test
  void shouldResolveAdditionalJwkSetUrisByRegistrationIdWithoutIssuerUri() {
    final var additionalUris = List.of("https://secondary.example.com/jwks");
    final var converter = converterWith(Map.of("oidc", additionalUris));
    final var registration = mockRegistration("oidc");

    converter.getJwtDecoder(registration);

    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(registration, additionalUris);
  }

  @Test
  void shouldResolveAdditionalJwkSetUrisPerRegistration() {
    final var defaultUris = List.of("https://default.example.com/jwks");
    final var entraUris = List.of("https://entra.example.com/jwks");
    final var converter = converterWith(Map.of("oidc", defaultUris, "entra", entraUris));
    final var defaultRegistration = mockRegistration("oidc");
    final var entraRegistration = mockRegistration("entra");

    converter.getJwtDecoder(defaultRegistration);
    converter.getJwtDecoder(entraRegistration);

    verify(oidcAccessTokenDecoderFactory)
        .createAccessTokenDecoder(defaultRegistration, defaultUris);
    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(entraRegistration, entraUris);
  }

  @Test
  void shouldPassNoAdditionalJwkSetUrisForUnknownRegistration() {
    final var converter = converterWith(Map.of("other", List.of("https://other.example.com/jwks")));
    final var registration = mockRegistration("oidc");

    converter.getJwtDecoder(registration);

    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(registration, null);
  }

  private OidcUserAuthenticationConverter converterWith(
      final Map<String, List<String>> additionalJwkSetUrisByRegistrationId) {
    return new OidcUserAuthenticationConverter(
        authorizedClientRepository,
        oidcAccessTokenDecoderFactory,
        tokenClaimsConverter,
        request,
        new AdditionalJwkSetUrisByRegistrationId(additionalJwkSetUrisByRegistrationId));
  }

  @SuppressWarnings("unchecked")
  private static OAuth2AuthenticationToken mockAuthToken(final String registrationId) {
    final var t = mock(OAuth2AuthenticationToken.class);
    when(t.getAuthorizedClientRegistrationId()).thenReturn(registrationId);
    return t;
  }

  /**
   * No {@code providerDetails}/{@code issuerUri} stubbing: {@link
   * OidcUserAuthenticationConverter#getJwtDecoder} resolves supplementary key sets by registration
   * ID alone, so a registration configured without {@code issuer-uri} is indistinguishable from one
   * configured with it. Stubbing the issuer here would be an unnecessary stubbing under strict
   * stubs, which is itself the assertion that the issuer is no longer consulted.
   */
  private static ClientRegistration mockRegistration(final String id) {
    final var r = mock(ClientRegistration.class);
    when(r.getRegistrationId()).thenReturn(id);
    return r;
  }
}
