/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcPrincipalClaims;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Builds a {@link VerifiedJwt} for tests outside this package, as a decoder of the library does.
 */
public final class VerifiedJwts {

  private VerifiedJwts() {}

  public static VerifiedJwt of(final Jwt jwt, final OidcPrincipalClaims principalClaims) {
    return new VerifiedJwt(jwt, principalClaims);
  }
}
