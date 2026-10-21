/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcPrincipalClaims;
import java.time.Instant;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@ExtendWith(MockitoExtension.class)
class VerifiedJwtDecoderTest {

  private static final String ISSUER = "https://idp.example.com";
  private static final String USER_INFO_URI = ISSUER + "/userinfo";

  @Mock private JwtDecoder delegate;

  @BeforeEach
  void setUp() {
    when(delegate.decode("token")).thenReturn(jwt());
  }

  @Test
  void shouldTagTheTokenWithTheClaimsOfTheProviderThatVerifiedIt() {
    // given
    final var named = OidcConfiguration.builder().usernameClaim("upn").build();
    final var defaultSlot = OidcConfiguration.builder().clientIdClaim("azp").build();
    final var decoder =
        VerifiedJwtDecoder.withClaims(
            delegate, owner("entra"), Map.of("entra", named), defaultSlot);

    // when
    final var jwt = (VerifiedJwt) decoder.decode("token");

    // then - the provider's own claim, and the client-id claim it inherits from the default slot
    assertThat(jwt.principalClaims()).contains(OidcPrincipalClaims.resolve(named, defaultSlot));
    assertThat(jwt.principalClaims().orElseThrow().clientIdClaim()).isEqualTo("azp");
    // the default decoder leaves the UserInfo use to the claims provider
    assertThat(jwt.decidesUserInfo()).isFalse();
  }

  @Test
  void shouldTagTheTokenOfTheDefaultSlotWithoutClaims() {
    // given
    final var defaultSlot = OidcConfiguration.builder().usernameClaim("email").build();
    final var decoder =
        VerifiedJwtDecoder.withClaims(
            delegate, owner("oidc"), Map.of("oidc", defaultSlot), defaultSlot);

    // when / then
    assertThat(((VerifiedJwt) decoder.decode("token")).principalClaims()).isEmpty();
  }

  /** A registration of a host repository that no provider describes uses the default converter. */
  @Test
  void shouldTagTheTokenOfAnUnconfiguredRegistrationWithoutClaims() {
    // given
    final var decoder =
        VerifiedJwtDecoder.withClaims(
            delegate, owner("host-only"), Map.of(), new OidcConfiguration());

    // when / then
    assertThat(((VerifiedJwt) decoder.decode("token")).principalClaims()).isEmpty();
  }

  @Test
  void shouldTagTheTokenOfAScopeWithTheUserInfoEndpointOfItsProvider() {
    // given
    final var provider = OidcConfiguration.builder().userInfoEnabled(true).build();
    final var decoder =
        VerifiedJwtDecoder.withClaimsAndUserInfo(
            delegate,
            owner("b"),
            Map.of("b", provider),
            new OidcConfiguration(),
            registrations("b", USER_INFO_URI));

    // when
    final var jwt = (VerifiedJwt) decoder.decode("token");

    // then
    assertThat(jwt.decidesUserInfo()).isTrue();
    assertThat(jwt.userInfoEnabled()).isTrue();
    assertThat(jwt.userInfoUri()).isEqualTo(USER_INFO_URI);
  }

  /** The scope's provider disables UserInfo: the token says so, and needs no registration. */
  @Test
  void shouldTagTheTokenOfAScopeWhoseProviderDisablesUserInfo() {
    // given
    final var provider = OidcConfiguration.builder().userInfoEnabled(false).build();
    final var decoder =
        VerifiedJwtDecoder.withClaimsAndUserInfo(
            delegate,
            owner("b"),
            Map.of("b", provider),
            new OidcConfiguration(),
            registrationId -> {
              throw new AssertionError("no registration needed");
            });

    // when
    final var jwt = (VerifiedJwt) decoder.decode("token");

    // then
    assertThat(jwt.decidesUserInfo()).isTrue();
    assertThat(jwt.userInfoEnabled()).isFalse();
  }

  private static Function<String, String> owner(final String registrationId) {
    return issuer -> ISSUER.equals(issuer) ? registrationId : null;
  }

  private static Function<String, ClientRegistration> registrations(
      final String registrationId, final String userInfoUri) {
    final var registration =
        ClientRegistration.withRegistrationId(registrationId)
            .clientId("client")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/cb")
            .authorizationUri(ISSUER + "/auth")
            .tokenUri(ISSUER + "/token")
            .jwkSetUri(ISSUER + "/jwks")
            .userInfoUri(userInfoUri)
            .issuerUri(ISSUER)
            .build();
    return id -> registrationId.equals(id) ? registration : null;
  }

  private static Jwt jwt() {
    return Jwt.withTokenValue("token")
        .header("alg", "RS256")
        .claim("iss", ISSUER)
        .claim("sub", "alice")
        .issuedAt(Instant.parse("2026-01-01T00:00:00Z"))
        .expiresAt(Instant.parse("2026-01-01T01:00:00Z"))
        .build();
  }
}
