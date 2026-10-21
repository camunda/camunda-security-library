/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.Map;
import org.springframework.util.StringUtils;

/**
 * Looks a token's issuer up in a map keyed by configured {@code issuer-uri}s, tolerating a trailing
 * slash the two don't share.
 *
 * <p>Identity providers are inconsistent about the trailing slash: Entra ID's discovery document
 * declares {@code .../v2.0}, Okta's has none, Auth0's has one. Operators copy either form into
 * {@code issuer-uri}. Discovery then settles on the provider's form (see {@link
 * ScopedClientRegistrationFactory}), and the provider's tokens carry it in {@code iss}, so a lookup
 * by {@code iss} in a map keyed by the configured form would miss. See camunda/camunda#61896.
 *
 * <p>The exact issuer always wins, so two providers configured as {@code https://idp} and {@code
 * https://idp/} each keep their own tokens. Only routing is tolerant: the registration a token
 * reaches still validates {@code iss} against its own issuer exactly.
 */
public final class IssuerUris {

  private IssuerUris() {}

  /**
   * @return the value for {@code issuer}, else for its {@linkplain #withToggledTrailingSlash other
   *     form}, else {@code null}
   */
  public static <V> V lookup(final Map<String, V> byIssuer, final String issuer) {
    if (issuer == null) {
      return null;
    }
    final var exact = byIssuer.get(issuer);
    if (exact != null) {
      return exact;
    }
    final var alternative = withToggledTrailingSlash(issuer);
    return alternative != null ? byIssuer.get(alternative) : null;
  }

  /**
   * The issuer with its trailing slash removed, or with one added: {@code https://idp/v2.0/} and
   * {@code https://idp/v2.0} give each other.
   *
   * @return the other form, or {@code null} for a value that has no path to trim or is otherwise
   *     not a plain issuer URL
   */
  public static String withToggledTrailingSlash(final String issuer) {
    if (!StringUtils.hasText(issuer) || issuer.contains("?") || issuer.contains("#")) {
      return null;
    }
    if (!issuer.endsWith("/")) {
      return issuer + "/";
    }
    final var trimmed = issuer.substring(0, issuer.length() - 1);
    // Never trim into an empty or scheme-only authority, such as "https:/".
    return trimmed.endsWith("/") || !trimmed.contains("://") || trimmed.endsWith(":/")
        ? null
        : trimmed;
  }
}
