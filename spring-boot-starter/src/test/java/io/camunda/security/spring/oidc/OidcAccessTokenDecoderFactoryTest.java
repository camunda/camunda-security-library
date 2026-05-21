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

import com.nimbusds.jose.KeySourceException;
import java.io.IOException;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

class OidcAccessTokenDecoderFactoryTest {

  @Test
  void wrapMapsBadJwtKeySourceCausedJwtExceptionToBadJwtException() {
    // The delegate behaves like NimbusJwtDecoder when IssuerAwareJWSKeySelector throws
    // BadJwtKeySourceException for a token-level fault (unknown / missing iss): it catches the
    // KeySourceException (a JOSEException) and rewraps it as a generic JwtException — which
    // Spring Security would treat as a 500 service error rather than a 401 invalid_token.
    final var keySourceCause = new BadJwtKeySourceException("Unknown issuer 'https://nope'");
    final JwtDecoder delegate =
        token -> {
          throw new JwtException(
              "An error occurred while attempting to decode the Jwt: "
                  + keySourceCause.getMessage(),
              keySourceCause);
        };

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThatThrownBy(() -> wrapped.decode("any-token"))
        .isInstanceOf(BadJwtException.class)
        .hasCause(keySourceCause);
  }

  @Test
  void wrapPropagatesGenericKeySourceCausedJwtExceptionUnchanged() {
    // A plain KeySourceException — e.g. from CompositeJWKSource on JWKS fetch failure, or
    // Nimbus's RemoteJWKSet on network/IO errors — represents an infrastructure fault, NOT a
    // bad token. Mapping it to BadJwtException would surface IdP outages as misleading 401s
    // and hide the real problem from operators. Must stay a generic JwtException → 500.
    final var infrastructureCause =
        new KeySourceException("Couldn't retrieve JWK set", new IOException("connect timeout"));
    final var original =
        new JwtException(
            "An error occurred while attempting to decode the Jwt: "
                + infrastructureCause.getMessage(),
            infrastructureCause);
    final JwtDecoder delegate =
        token -> {
          throw original;
        };

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThatThrownBy(() -> wrapped.decode("any-token")).isSameAs(original);
  }

  @Test
  void wrapPropagatesBadJwtExceptionUnchanged() {
    // A BadJwtException from the delegate must pass through as-is — it's already the right
    // type for Spring Security's invalid_token mapping.
    final var original = new BadJwtException("malformed");
    final JwtDecoder delegate =
        token -> {
          throw original;
        };

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThatThrownBy(() -> wrapped.decode("any-token")).isSameAs(original);
  }

  @Test
  void wrapPropagatesNonKeySourceJwtExceptionUnchanged() {
    // A JwtException with some other cause is *not* an authentication / bad-token problem and
    // should keep its semantic — e.g. a parser error or any other non-KeySourceException flow.
    final var cause = new RuntimeException("unexpected");
    final var original = new JwtException("Some other failure", cause);
    final JwtDecoder delegate =
        token -> {
          throw original;
        };

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThatThrownBy(() -> wrapped.decode("any-token")).isSameAs(original);
  }

  @Test
  void wrapPassesThroughSuccessfulDecode() {
    final var expected =
        Jwt.withTokenValue("tok")
            .header("alg", "RS256")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
            .claims(c -> c.put("sub", "alice"))
            .build();
    final JwtDecoder delegate = token -> expected;

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThat(wrapped.decode("any-token")).isSameAs(expected);
  }

  @Test
  void wrapHandlesIndirectBadJwtKeySourceCauseOnlyAtImmediateLevel() {
    // The NimbusJwtDecoder behaviour we observe in practice always puts the
    // BadJwtKeySourceException as the *immediate* cause of the JwtException. Anything deeper
    // is a different failure shape we don't want to misclassify, so the wrap only inspects
    // ex.getCause().
    final var deepCause = new BadJwtKeySourceException("buried");
    final var middle = new RuntimeException("intermediate", deepCause);
    final var jwtException = new JwtException("decode failed", middle);
    final JwtDecoder delegate =
        token -> {
          throw jwtException;
        };

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThatThrownBy(() -> wrapped.decode("any-token")).isSameAs(jwtException);
  }
}
