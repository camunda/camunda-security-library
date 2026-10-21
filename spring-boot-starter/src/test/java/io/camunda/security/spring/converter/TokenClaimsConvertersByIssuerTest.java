/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.oidc.OidcPrincipalClaims;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.oidc.VerifiedJwts;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.Jwt;

@ExtendWith(MockitoExtension.class)
class TokenClaimsConvertersByIssuerTest {

  private static final String ISSUER = "https://entra.example.com";
  private static final OidcPrincipalClaims UPN = new OidcPrincipalClaims("upn", null, false);

  @Mock private LazyTokenClaimsConverter entraConverter;
  @Mock private LazyTokenClaimsConverter claimsConverter;
  @Mock private LazyTokenClaimsConverter defaultConverter;

  @Test
  void returnsConverterForMatchingIssuer() {
    final var converters = new TokenClaimsConvertersByIssuer(Map.of(ISSUER, entraConverter));

    assertThat(converters.getOrDefault(ISSUER, defaultConverter)).isSameAs(entraConverter);
  }

  @Test
  void returnsDefaultConverterWhenIssuerDoesNotMatchAnyEntry() {
    final var converters = new TokenClaimsConvertersByIssuer(Map.of(ISSUER, entraConverter));

    assertThat(converters.getOrDefault("https://auth0.example.com", defaultConverter))
        .isSameAs(defaultConverter);
  }

  /** The issuer map serves decoders a host builds itself, whose routing is unknown: exact. */
  @Test
  void looksTheIssuerUpExactly() {
    final var converters = new TokenClaimsConvertersByIssuer(Map.of(ISSUER + "/", entraConverter));

    assertThat(converters.getOrDefault(ISSUER, defaultConverter)).isSameAs(defaultConverter);
  }

  @Test
  void returnsDefaultConverterWhenIssuerIsNull() {
    final var converters = new TokenClaimsConvertersByIssuer(Map.of(ISSUER, entraConverter));

    assertThat(converters.getOrDefault(null, defaultConverter)).isSameAs(defaultConverter);
  }

  @Test
  void treatsNullMapAsEmpty() {
    final var converters = new TokenClaimsConvertersByIssuer(null);

    assertThat(converters.getOrDefault(ISSUER, defaultConverter)).isSameAs(defaultConverter);
    assertThat(converters.byIssuer()).isEmpty();
  }

  /**
   * A token a decoder of the library verified carries the claims of its provider, and is mapped
   * with them, even where the issuer map holds another provider of the same issuer.
   */
  @Test
  void mapsAVerifiedTokenWithTheConverterOfTheClaimsItCarries() {
    final var converters =
        new TokenClaimsConvertersByIssuer(
            Map.of(ISSUER, entraConverter), claims -> UPN.equals(claims) ? claimsConverter : null);

    assertThat(converters.forToken(VerifiedJwts.of(jwt(), UPN), defaultConverter))
        .isSameAs(claimsConverter);
  }

  /**
   * The provider that verified the token uses the default converter: the issuer map is not read.
   */
  @Test
  void mapsAVerifiedTokenWithoutClaimsWithTheDefaultConverter() {
    final var converters =
        new TokenClaimsConvertersByIssuer(
            Map.of(ISSUER, entraConverter), claims -> claimsConverter);

    assertThat(converters.forToken(VerifiedJwts.of(jwt(), null), defaultConverter))
        .isSameAs(defaultConverter);
  }

  @Test
  void looksATokenOfAnotherDecoderUpByIssuer() {
    final var converters =
        new TokenClaimsConvertersByIssuer(
            Map.of(ISSUER, entraConverter), claims -> claimsConverter);

    assertThat(converters.forToken(jwt(), defaultConverter)).isSameAs(entraConverter);
  }

  /** A map a host builds without the claims lookup reads the issuer for every token. */
  @Test
  void looksAVerifiedTokenUpByIssuerWithoutAClaimsLookup() {
    final var converters = new TokenClaimsConvertersByIssuer(Map.of(ISSUER, entraConverter));

    assertThat(converters.forToken(VerifiedJwts.of(jwt(), UPN), defaultConverter))
        .isSameAs(entraConverter);
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
