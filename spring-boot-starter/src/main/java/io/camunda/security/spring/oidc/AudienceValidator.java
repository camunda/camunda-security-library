/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Validates the audience of a JWT token. A token can have multiple audiences, but at least one of
 * the valid audiences must be present.
 */
public final class AudienceValidator implements OAuth2TokenValidator<Jwt> {

  private final Set<String> validAudiences;

  /**
   * Creates a new validator with the given valid audiences.
   *
   * @param validAudiences the valid audiences. Must not be empty.
   */
  public AudienceValidator(final Set<String> validAudiences) {
    if (validAudiences.isEmpty()) {
      throw new IllegalArgumentException("At least one valid audience must be provided");
    }
    this.validAudiences = Set.copyOf(validAudiences);
  }

  @Override
  public OAuth2TokenValidatorResult validate(final Jwt token) {
    final var tokenAudiences = Objects.requireNonNullElse(token.getAudience(), List.<String>of());

    // Iterate over token audiences first, usually there is only one
    for (final var tokenAudience : tokenAudiences) {
      if (validAudiences.contains(tokenAudience)) {
        return OAuth2TokenValidatorResult.success();
      }
    }

    return OAuth2TokenValidatorResult.failure(
        new OAuth2Error(
            OAuth2ErrorCodes.INVALID_TOKEN,
            "Token audiences are %s, expected at least one of %s"
                .formatted(tokenAudiences, validAudiences),
            null));
  }
}
