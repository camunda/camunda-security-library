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
import java.util.function.Function;

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
 * @param byIssuer the converters by configured issuer-uri
 * @param toleratesTrailingSlash see {@link #getOrDefault}
 * @param byRegisteredIssuer when not {@code null}, decides instead of {@code byIssuer}: the
 *     converter of the registration a token's issuer is routed to, or {@code null} for the default
 *     one. For a host's own {@code ClientRegistrationRepository}, whose registrations can carry an
 *     issuer other than the configured issuer-uri, as discovery resolves {@code https://idp/realm/}
 *     to the {@code https://idp/realm} the provider declares.
 */
public record TokenClaimsConvertersByIssuer(
    Map<String, LazyTokenClaimsConverter> byIssuer,
    boolean toleratesTrailingSlash,
    Function<String, LazyTokenClaimsConverter> byRegisteredIssuer) {

  public TokenClaimsConvertersByIssuer {
    byIssuer = byIssuer != null ? Map.copyOf(byIssuer) : Map.of();
  }

  /** Exact lookup by issuer, for a map whose keys are the issuers tokens carry. */
  public TokenClaimsConvertersByIssuer(final Map<String, LazyTokenClaimsConverter> byIssuer) {
    this(byIssuer, false);
  }

  /** Lookup in {@code byIssuer} only. */
  public TokenClaimsConvertersByIssuer(
      final Map<String, LazyTokenClaimsConverter> byIssuer, final boolean toleratesTrailingSlash) {
    this(byIssuer, toleratesTrailingSlash, null);
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
    final var converter = issuer != null ? lookup(issuer) : null;
    return converter != null ? converter : defaultConverter;
  }

  private LazyTokenClaimsConverter lookup(final String issuer) {
    if (byRegisteredIssuer != null) {
      return byRegisteredIssuer.apply(issuer);
    }
    return toleratesTrailingSlash ? IssuerUris.lookup(byIssuer, issuer) : byIssuer.get(issuer);
  }
}
