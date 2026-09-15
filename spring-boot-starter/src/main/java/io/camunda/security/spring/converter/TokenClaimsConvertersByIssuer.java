/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import io.camunda.security.core.authz.LazyTokenClaimsConverter;
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
public record TokenClaimsConvertersByIssuer(Map<String, LazyTokenClaimsConverter> byIssuer) {

  public TokenClaimsConvertersByIssuer {
    byIssuer = byIssuer != null ? Map.copyOf(byIssuer) : Map.of();
  }

  /**
   * @param issuer the bearer token's issuer, or {@code null} if absent
   * @param defaultConverter returned when {@code issuer} is {@code null} or has no entry here
   */
  public LazyTokenClaimsConverter getOrDefault(
      final String issuer, final LazyTokenClaimsConverter defaultConverter) {
    return issuer == null ? defaultConverter : byIssuer.getOrDefault(issuer, defaultConverter);
  }
}
