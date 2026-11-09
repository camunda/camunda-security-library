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
import io.camunda.security.spring.oidc.ClientRegistrationMetadata;
import io.camunda.security.spring.oidc.OidcAccessTokenDecoderFactory;
import io.camunda.security.spring.oidc.TokenValidatorFactory;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
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
  void shouldLoadTheAuthorizedClientOnlyOncePerLogin() {
    // given a custom repository can read the client from a remote store
    final var token = mockAuthToken("oidc");
    final var registration =
        registration(
            "oidc",
            "https://idp/jwks",
            "https://idp",
            Map.of(ClientRegistrationMetadata.PREFER_ID_TOKEN_CLAIMS, false));
    final var now = Instant.now();
    final var client =
        new OAuth2AuthorizedClient(
            registration,
            "alice",
            new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "at", now, now.plusSeconds(60)));
    when(authorizedClientRepository.loadAuthorizedClient("oidc", token, request))
        .thenReturn(client);
    final var jwt = Jwt.withTokenValue("at").header("alg", "RS256").claim("sub", "alice").build();
    when(jwtDecoder.decode("at")).thenReturn(jwt);
    when(tokenClaimsConverter.convert(jwt.getClaims()))
        .thenReturn(CamundaAuthentication.of(b -> b.user("alice")));

    // when
    converter.convert(token);

    // then
    verify(authorizedClientRepository).loadAuthorizedClient("oidc", token, request);
  }

  @Test
  void shouldNotPreferIdTokenClaimsForATokenWithoutRegistrationId() {
    // given
    final var converter = converterWith(Map.of(), Map.of("oidc", true));
    final var token = mockAuthToken(null);
    final var principal = mock(OidcUser.class);
    when(token.getPrincipal()).thenReturn(principal);
    when(principal.getAttributes()).thenReturn(Map.of("sub", "alice"));
    when(tokenClaimsConverter.convert(Map.of("sub", "alice")))
        .thenReturn(CamundaAuthentication.of(b -> b.user("alice")));

    // when
    converter.convert(token);

    // then the access-token path ran, and found no client
    verify(authorizedClientRepository).loadAuthorizedClient(null, token, request);
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

  @Test
  void shouldBuildOneDecoderPerProviderSettingForASharedRegistrationId() {
    final var converter = converterWith(Map.of());
    final var registrationA = registration("oidc", "https://idp-a/jwks", "https://idp-a");
    final var registrationB = registration("oidc", "https://idp-b/jwks", "https://idp-b");
    final var registrationASecondLogin =
        registration("oidc", "https://idp-a/jwks", "https://idp-a");

    converter.getJwtDecoder(registrationA);
    converter.getJwtDecoder(registrationB);
    converter.getJwtDecoder(registrationASecondLogin);

    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(registrationA, null);
    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(registrationB, null);
    verify(oidcAccessTokenDecoderFactory, never())
        .createAccessTokenDecoder(registrationASecondLogin, null);
  }

  @Test
  void shouldBuildOneDecoderPerIssuerForAnOtherwiseEqualRegistration() {
    final var converter = converterWith(Map.of());
    final var issuerA = registration("oidc", "https://idp/jwks", "https://idp-a");
    final var issuerB = registration("oidc", "https://idp/jwks", "https://idp-b");

    converter.getJwtDecoder(issuerA);
    converter.getJwtDecoder(issuerB);

    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(issuerA, null);
    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(issuerB, null);
  }

  @Test
  void shouldBuildOneDecoderPerJwkSetUriForAnOtherwiseEqualRegistration() {
    final var converter = converterWith(Map.of());
    final var jwksA = registration("oidc", "https://idp/jwks-a", "https://idp");
    final var jwksB = registration("oidc", "https://idp/jwks-b", "https://idp");

    converter.getJwtDecoder(jwksA);
    converter.getJwtDecoder(jwksB);

    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(jwksA, null);
    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(jwksB, null);
  }

  @Test
  void shouldFailBeforeTheCacheLookupOnMalformedAudienceMetadata() {
    // given a decoder is cached for a registration without audiences
    final var converter = converterWith(Map.of());
    converter.getJwtDecoder(registration("oidc", "https://idp/jwks", "https://idp"));
    final var malformed =
        registration(
            "oidc",
            "https://idp/jwks",
            "https://idp",
            Map.of(TokenValidatorFactory.AUDIENCES_METADATA_KEY, "audience-x"));

    // when / then the malformed entry fails closed instead of reusing that decoder
    assertThatThrownBy(() -> converter.getJwtDecoder(malformed))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(TokenValidatorFactory.AUDIENCES_METADATA_KEY);
  }

  @Test
  void shouldShareTheDecoderForAudiencesThatOnlyDifferInTheirCollectionType() {
    final var converter = converterWith(Map.of());
    final var asList =
        registration(
            "oidc",
            "https://idp/jwks",
            "https://idp",
            Map.of(TokenValidatorFactory.AUDIENCES_METADATA_KEY, List.of("x", "y")));
    final var asSet =
        registration(
            "oidc",
            "https://idp/jwks",
            "https://idp",
            Map.of(TokenValidatorFactory.AUDIENCES_METADATA_KEY, Set.of("y", "x")));

    converter.getJwtDecoder(asList);
    converter.getJwtDecoder(asSet);

    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(asList, null);
    verify(oidcAccessTokenDecoderFactory, never()).createAccessTokenDecoder(asSet, null);
  }

  @Test
  void shouldBuildOneDecoderPerAudienceSetForAnOtherwiseEqualRegistration() {
    final var converter = converterWith(Map.of());
    final var withAudience =
        registration(
            "oidc",
            "https://idp/jwks",
            "https://idp",
            Map.of(TokenValidatorFactory.AUDIENCES_METADATA_KEY, List.of("audience-x")));
    final var withoutAudience =
        registration(
            "oidc",
            "https://idp/jwks",
            "https://idp",
            Map.of(TokenValidatorFactory.AUDIENCES_METADATA_KEY, List.of()));

    converter.getJwtDecoder(withAudience);
    converter.getJwtDecoder(withoutAudience);

    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(withAudience, null);
    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(withoutAudience, null);
  }

  @Test
  void shouldBuildOneDecoderPerAdditionalJwkSetForAnOtherwiseEqualRegistration() {
    final var converter = converterWith(Map.of());
    final var extraUris = List.of("https://idp/extra-jwks");
    final var withExtra =
        registration(
            "oidc",
            "https://idp/jwks",
            "https://idp",
            Map.of(ClientRegistrationMetadata.ADDITIONAL_JWK_SET_URIS, extraUris));
    final var withoutExtra =
        registration(
            "oidc",
            "https://idp/jwks",
            "https://idp",
            Map.of(ClientRegistrationMetadata.ADDITIONAL_JWK_SET_URIS, List.of()));

    converter.getJwtDecoder(withExtra);
    converter.getJwtDecoder(withoutExtra);

    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(withExtra, extraUris);
    verify(oidcAccessTokenDecoderFactory).createAccessTokenDecoder(withoutExtra, null);
  }

  private static ClientRegistration registration(
      final String id, final String jwkSetUri, final String issuer) {
    return registration(id, jwkSetUri, issuer, Map.of());
  }

  private static ClientRegistration registration(
      final String id,
      final String jwkSetUri,
      final String issuer,
      final Map<String, Object> extraMetadata) {
    final Map<String, Object> metadata = new HashMap<>(extraMetadata);
    metadata.put(ClientRegistrationMetadata.ISSUER, issuer);
    return ClientRegistration.withRegistrationId(id)
        .clientId("client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri(issuer + "/auth")
        .tokenUri(issuer + "/token")
        .jwkSetUri(jwkSetUri)
        .providerConfigurationMetadata(metadata)
        .build();
  }

  private OidcUserAuthenticationConverter converterWith(
      final Map<String, List<String>> additionalJwkSetUrisByRegistrationId,
      final Map<String, Boolean> preferIdTokenClaimsByRegistrationId) {
    return new OidcUserAuthenticationConverter(
        authorizedClientRepository,
        oidcAccessTokenDecoderFactory,
        tokenClaimsConverter,
        request,
        new AdditionalJwkSetUrisByRegistrationId(additionalJwkSetUrisByRegistrationId),
        preferIdTokenClaimsByRegistrationId);
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
