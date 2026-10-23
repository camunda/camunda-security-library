/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.oidc.OidcPrincipalClaims;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class VerifiedJwtTest {

  private static final OidcPrincipalClaims CLAIMS = new OidcPrincipalClaims("upn", "azp", true);

  @Test
  void shouldKeepTheTokenAndCarryThePrincipalClaims() {
    // given
    final var jwt = jwt();

    // when
    final var verified = new VerifiedJwt(jwt, CLAIMS);

    // then
    assertThat(verified.getTokenValue()).isEqualTo(jwt.getTokenValue());
    assertThat(verified.getClaims()).isEqualTo(jwt.getClaims());
    assertThat(verified.getHeaders()).isEqualTo(jwt.getHeaders());
    assertThat(verified.principalClaims()).contains(CLAIMS);
  }

  @Test
  void shouldCarryNoClaimsForAProviderOfTheDefaultConverter() {
    assertThat(new VerifiedJwt(jwt(), null).principalClaims()).isEmpty();
  }

  /** A session can hold the token, so the claims must survive serialization. */
  @Test
  void shouldKeepThePrincipalClaimsThroughSerialization() throws Exception {
    // given
    final var verified = new VerifiedJwt(jwt(), CLAIMS);

    // when
    final var bytes = new ByteArrayOutputStream();
    try (final var out = new ObjectOutputStream(bytes)) {
      out.writeObject(verified);
    }
    final Object restored;
    try (final var in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      restored = in.readObject();
    }

    // then
    assertThat(restored)
        .isInstanceOfSatisfying(
            VerifiedJwt.class, jwt -> assertThat(jwt.principalClaims()).contains(CLAIMS));
  }

  private static Jwt jwt() {
    return Jwt.withTokenValue("token")
        .header("alg", "RS256")
        .claim("iss", "https://idp.example.com")
        .claim("sub", "alice")
        .issuedAt(Instant.parse("2026-01-01T00:00:00Z"))
        .expiresAt(Instant.parse("2026-01-01T01:00:00Z"))
        .build();
  }
}
