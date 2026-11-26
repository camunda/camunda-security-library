/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import io.camunda.security.api.model.config.oidc.OidcPrincipalClaims;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.oidc.VerifiedJwt;
import java.util.Map;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

/**
 * Per-issuer {@link LazyTokenClaimsConverter} lookup for {@link OidcTokenAuthenticationConverter}.
 * See <a
 * href="https://github.com/camunda/camunda-security-library/blob/main/docs/adr/0024-per-issuer-token-claims-converter-map.md">ADR-0024</a>
 * for the design rationale.
 *
 * <p>Exposed as a dedicated type rather than a bare {@code Map<String, LazyTokenClaimsConverter>}:
 * Spring intercepts any injection point whose declared type is exactly {@code java.util.Map},
 * collecting all beans of the value type keyed by <em>bean name</em> instead of ever looking for a
 * bean of that {@code Map} type itself. Since a {@link LazyTokenClaimsConverter} bean already
 * exists (the default), a bare-{@code Map} injection point would silently receive {@code
 * {"lazyTokenClaimsConverter": <default instance>}} instead of this issuer-keyed map.
 *
 * <p>A token that a decoder of the library verified is a {@link VerifiedJwt}, which carries the
 * principal claims of the provider that verified it. {@link #forToken} maps such a token with those
 * claims, so a token is never mapped with the claim settings of a provider of another scope that
 * declares the same issuer. See <a
 * href="https://github.com/camunda/camunda-security-library/blob/main/docs/adr/0038-verified-token-carries-its-provider-claims.md">ADR-0038</a>.
 *
 * @param byIssuer the converters by configured issuer-uri, for a token that a decoder of the host
 *     verified
 * @param byPrincipalClaims the converter for the principal claims a {@link VerifiedJwt} carries;
 *     {@code null} to look a verified token up by issuer as well
 */
public record TokenClaimsConvertersByIssuer(
    Map<String, LazyTokenClaimsConverter> byIssuer,
    @Nullable Function<OidcPrincipalClaims, LazyTokenClaimsConverter> byPrincipalClaims) {

  public TokenClaimsConvertersByIssuer {
    byIssuer = byIssuer != null ? Map.copyOf(byIssuer) : Map.of();
  }

  /** Looks every token up by issuer. */
  public TokenClaimsConvertersByIssuer(final Map<String, LazyTokenClaimsConverter> byIssuer) {
    this(byIssuer, null);
  }

  /**
   * @param jwt the bearer token
   * @param defaultConverter returned for a verified token whose provider uses the default
   *     converter, and for a token of another decoder whose issuer has no entry here
   */
  public LazyTokenClaimsConverter forToken(
      final Jwt jwt, final LazyTokenClaimsConverter defaultConverter) {
    if (byPrincipalClaims != null && jwt instanceof final VerifiedJwt verified) {
      return verified.principalClaims().map(byPrincipalClaims).orElse(defaultConverter);
    }
    final var issuer = jwt.getClaims().get(JwtClaimNames.ISS);
    return getOrDefault(issuer == null ? null : issuer.toString(), defaultConverter);
  }

  /**
   * @param issuer the bearer token's issuer, or {@code null} if absent
   * @param defaultConverter returned when {@code issuer} is {@code null} or has no entry here
   */
  public LazyTokenClaimsConverter getOrDefault(
      final @Nullable String issuer, final LazyTokenClaimsConverter defaultConverter) {
    return issuer == null ? defaultConverter : byIssuer.getOrDefault(issuer, defaultConverter);
  }
}
