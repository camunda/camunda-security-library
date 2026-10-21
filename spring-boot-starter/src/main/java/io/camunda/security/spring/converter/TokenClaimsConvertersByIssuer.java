/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.oidc.IssuerUris;
import java.util.Map;

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
 */
public record TokenClaimsConvertersByIssuer(
    Map<String, LazyTokenClaimsConverter> byIssuer, boolean toleratesTrailingSlash) {

  public TokenClaimsConvertersByIssuer {
    byIssuer = byIssuer != null ? Map.copyOf(byIssuer) : Map.of();
  }

  /** Exact lookup by issuer, for a map whose keys are the issuers tokens carry. */
  public TokenClaimsConvertersByIssuer(final Map<String, LazyTokenClaimsConverter> byIssuer) {
    this(byIssuer, false);
  }

  /**
   * @param issuer the bearer token's issuer, or {@code null} if absent
   * @param defaultConverter returned when {@code issuer} is {@code null} or has no entry here. With
   *     {@link #toleratesTrailingSlash}, an entry for the issuer's other trailing-slash form counts
   *     too (see {@link IssuerUris}): set only where the access-token decoder routes by the
   *     provider configuration too. A decoder that routes a host's resolved registrations exactly
   *     needs an exact lookup here, or a token of a registration without an entry would get its
   *     slash twin's converter instead of the default.
   */
  public LazyTokenClaimsConverter getOrDefault(
      final String issuer, final LazyTokenClaimsConverter defaultConverter) {
    final var converter =
        toleratesTrailingSlash
            ? IssuerUris.lookup(byIssuer, issuer)
            : issuer != null ? byIssuer.get(issuer) : null;
    return converter != null ? converter : defaultConverter;
  }
}
