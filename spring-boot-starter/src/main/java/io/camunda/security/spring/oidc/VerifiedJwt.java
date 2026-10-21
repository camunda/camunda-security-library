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
 * <p>A decoder of a scope also records whether the verifying provider uses UserInfo, and its
 * endpoint, so the claims provider does not pick the endpoint of another provider by issuer.
 *
 * <p>The claims are plain values, so the token stays serializable, as {@link Jwt} is.
 */
public final class VerifiedJwt extends Jwt {

  private static final long serialVersionUID = 1L;

  private final String usernameClaim;
  private final String clientIdClaim;
  private final boolean preferUsernameClaim;
  private final boolean hasPrincipalClaims;
  private final boolean decidesUserInfo;
  private final boolean userInfoEnabled;
  private final String userInfoUri;

  /**
   * @param jwt the verified token
   * @param principalClaims the principal claims of the provider that verified it, or {@code null}
   *     when that provider uses the default claim converter
   */
  VerifiedJwt(final Jwt jwt, final OidcPrincipalClaims principalClaims) {
    this(jwt, principalClaims, false, false, null);
  }

  /**
   * @param jwt the verified token
   * @param principalClaims the principal claims of the provider that verified it, or {@code null}
   *     when that provider uses the default claim converter
   * @param userInfoEnabled whether the provider that verified the token uses UserInfo
   * @param userInfoUri the UserInfo endpoint of the registration that verified the token, or {@code
   *     null} when it exposes none
   */
  VerifiedJwt(
      final Jwt jwt,
      final OidcPrincipalClaims principalClaims,
      final boolean userInfoEnabled,
      final String userInfoUri) {
    this(jwt, principalClaims, true, userInfoEnabled, userInfoUri);
  }

  private VerifiedJwt(
      final Jwt jwt,
      final OidcPrincipalClaims principalClaims,
      final boolean decidesUserInfo,
      final boolean userInfoEnabled,
      final String userInfoUri) {
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
    this.decidesUserInfo = decidesUserInfo;
    this.userInfoEnabled = userInfoEnabled;
    this.userInfoUri = userInfoUri;
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

  /**
   * Whether the decoder recorded the UserInfo use of the provider that verified the token. A
   * decoder of a scope does, because the claims provider is shared by all scopes and would
   * otherwise pick a provider by issuer. Without it, the claims provider decides by issuer.
   */
  public boolean decidesUserInfo() {
    return decidesUserInfo;
  }

  /** Whether the provider that verified the token uses UserInfo; see {@link #decidesUserInfo()}. */
  public boolean userInfoEnabled() {
    return userInfoEnabled;
  }

  /**
   * The UserInfo endpoint of the registration that verified the token, or {@code null} when it
   * exposes none; see {@link #decidesUserInfo()}.
   */
  public String userInfoUri() {
    return userInfoUri;
  }
}
