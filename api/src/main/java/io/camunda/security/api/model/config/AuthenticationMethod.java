/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import java.util.Arrays;

/**
 * Authentication method selected by the host via {@code camunda.security.authentication.method}.
 *
 * <p>The enum models the supported top-level authentication modes exposed by CSL configuration.
 * Spring property binding and manual parsing both resolve configuration values case-insensitively.
 */
public enum AuthenticationMethod {
  /** HTTP Basic authentication. */
  BASIC,

  /** OpenID Connect authentication. */
  OIDC;

  /**
   * Parses a configured authentication method value.
   *
   * @return the matching {@link AuthenticationMethod}, or {@code null} if {@code value} is {@code
   *     null}
   * @throws IllegalArgumentException if {@code value} is non-null but does not match any known
   *     method
   */
  public static AuthenticationMethod parse(final String value) {
    if (value == null) {
      return null;
    }
    return Arrays.stream(values())
        .filter(method -> method.name().equalsIgnoreCase(value))
        .findFirst()
        .orElseThrow(
            () -> new IllegalArgumentException("unsupported authentication method: " + value));
  }
}
