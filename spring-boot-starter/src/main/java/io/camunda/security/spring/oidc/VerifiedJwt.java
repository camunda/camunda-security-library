/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcPrincipalClaims;
import java.util.Optional;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * A {@link Jwt} that a decoder of the library verified, with the principal claims of the provider
 * whose registration verified it. {@code OidcTokenAuthenticationConverter} maps the token with
 * these claims, so the claim settings always come from the provider that verified the token, also
 * where the decoder belongs to one scope and a provider of another scope declares the same issuer.
 * See <a
 * href="https://github.com/camunda/camunda-security-library/blob/main/docs/adr/0038-verified-token-carries-its-provider-claims.md">ADR-0038</a>.
 *
 * <p>The claims are plain values, so the token stays serializable, as {@link Jwt} is.
 */
public final class VerifiedJwt extends Jwt {

  private static final long serialVersionUID = 1L;

  private final String usernameClaim;
  private final String clientIdClaim;
  private final boolean preferUsernameClaim;
  private final boolean hasPrincipalClaims;

  /**
   * @param jwt the verified token
   * @param principalClaims the principal claims of the provider that verified it, or {@code null}
   *     when that provider uses the default claim converter
   */
  VerifiedJwt(final Jwt jwt, final OidcPrincipalClaims principalClaims) {
    super(
        jwt.getTokenValue(),
        jwt.getIssuedAt(),
        jwt.getExpiresAt(),
        jwt.getHeaders(),
        jwt.getClaims());
    hasPrincipalClaims = principalClaims != null;
    usernameClaim = hasPrincipalClaims ? principalClaims.usernameClaim() : null;
    clientIdClaim = hasPrincipalClaims ? principalClaims.clientIdClaim() : null;
    preferUsernameClaim = hasPrincipalClaims && principalClaims.preferUsernameClaim();
  }

  /**
   * @return the principal claims of the provider that verified the token, or empty when that
   *     provider uses the default claim converter, as the default slot of the global configuration
   *     does
   */
  public Optional<OidcPrincipalClaims> principalClaims() {
    return hasPrincipalClaims
        ? Optional.of(new OidcPrincipalClaims(usernameClaim, clientIdClaim, preferUsernameClaim))
        : Optional.empty();
  }
}
