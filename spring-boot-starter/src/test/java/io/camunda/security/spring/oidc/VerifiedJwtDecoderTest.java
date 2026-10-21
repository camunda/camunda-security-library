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
import io.camunda.security.spring.oidc.OidcAccessTokenDecoderFactory.OwnedDecoder;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@ExtendWith(MockitoExtension.class)
class VerifiedJwtDecoderTest {

  private static final String ISSUER = "https://idp.example.com";

  @Mock private JwtDecoder delegate;

  @Test
  void shouldTagTheTokenWithTheClaimsOfTheProviderThatVerifiedIt() {
    // given
    final var named = OidcConfiguration.builder().usernameClaim("upn").build();
    final var defaultSlot = OidcConfiguration.builder().clientIdClaim("azp").build();
    final var decoder = decoder(Map.of("entra", named), "entra", defaultSlot, null);

    // when
    final var jwt = decoder.decode("token");

    // then - the provider's own claim, and the client-id claim it inherits from the default slot
    assertThat(jwt)
        .isInstanceOfSatisfying(
            VerifiedJwt.class,
            verified ->
                assertThat(verified.principalClaims())
                    .contains(OidcPrincipalClaims.resolve(named, defaultSlot)));
    assertThat(((VerifiedJwt) jwt).principalClaims().orElseThrow().clientIdClaim())
        .isEqualTo("azp");
  }

  @Test
  void shouldTagTheTokenOfTheDefaultConverterSlotWithoutClaims() {
    // given
    final var defaultSlot = OidcConfiguration.builder().usernameClaim("email").build();
    final var decoder = decoder(Map.of("oidc", defaultSlot), "oidc", defaultSlot, defaultSlot);

    // when / then
    assertThat(((VerifiedJwt) decoder.decode("token")).principalClaims()).isEmpty();
  }

  /** A registration of a host repository that no provider describes uses the default converter. */
  @Test
  void shouldTagTheTokenOfAnUnconfiguredRegistrationWithoutClaims() {
    // given
    final var decoder = decoder(Map.of(), "host-only", new OidcConfiguration(), null);

    // when / then
    assertThat(((VerifiedJwt) decoder.decode("token")).principalClaims()).isEmpty();
  }

  private JwtDecoder decoder(
      final Map<String, OidcConfiguration> providers,
      final String owner,
      final OidcConfiguration defaultSlot,
      final OidcConfiguration defaultConverterSlot) {
    when(delegate.decode("token")).thenReturn(jwt());
    return VerifiedJwtDecoder.of(
        new OwnedDecoder(delegate, issuer -> ISSUER.equals(issuer) ? owner : null),
        providers,
        defaultSlot,
        defaultConverterSlot);
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
