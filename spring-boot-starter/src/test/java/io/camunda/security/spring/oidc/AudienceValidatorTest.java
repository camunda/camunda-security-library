/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;

final class AudienceValidatorTest {

  @Test
  void shouldThrowExceptionWhenNoValidAudiencesProvided() {
    assertThatThrownBy(() -> new AudienceValidator(Set.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("At least one valid audience must be provided");
  }

  @Test
  void shouldValidateTokenWithMatchingAudience() {
    final var validator = new AudienceValidator(Set.of("valid-audience"));
    final var token = createJwtWithAudiences(List.of("valid-audience"));
    assertThat(validator.validate(token).hasErrors()).isFalse();
  }

  @Test
  void shouldValidateTokenWithOneMatchingAudienceAmongMany() {
    final var validator = new AudienceValidator(Set.of("valid-audience-1", "valid-audience-2"));
    final var token = createJwtWithAudiences(List.of("invalid-audience", "valid-audience-2"));
    assertThat(validator.validate(token).hasErrors()).isFalse();
  }

  @Test
  void shouldRejectTokenWithNoMatchingAudience() {
    final var validator = new AudienceValidator(Set.of("valid-audience"));
    final var token = createJwtWithAudiences(List.of("invalid-audience"));

    final var result = validator.validate(token);
    assertThat(result.hasErrors()).isTrue();

    final var errors = result.getErrors();
    assertThat(errors).hasSize(1);

    final var error = errors.iterator().next();
    assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
    assertThat(error.getDescription())
        .isEqualTo(
            "Token audiences are [invalid-audience], expected at least one of [valid-audience]");
  }

  @Test
  void shouldValidateTokenWithMultipleValidAudiences() {
    final var validator =
        new AudienceValidator(Set.of("valid-audience-1", "valid-audience-2", "valid-audience-3"));
    final var token = createJwtWithAudiences(List.of("valid-audience-2"));
    assertThat(validator.validate(token).hasErrors()).isFalse();
  }

  @Test
  void shouldNotReflectChangesInOriginalAudiencesSet() {
    final var validAudiences = new HashSet<String>();
    validAudiences.add("valid-audience");
    final var validator = new AudienceValidator(validAudiences);

    validAudiences.clear();
    validAudiences.add("new-audience");

    final var tokenWithOriginalAudience = createJwtWithAudiences(List.of("valid-audience"));
    assertThat(validator.validate(tokenWithOriginalAudience).hasErrors()).isFalse();

    final var tokenWithNewAudience = createJwtWithAudiences(List.of("new-audience"));
    assertThat(validator.validate(tokenWithNewAudience).hasErrors()).isTrue();
  }

  private static Jwt createJwtWithAudiences(final List<String> audiences) {
    return new Jwt(
        "token-value",
        Instant.now(),
        Instant.now().plusSeconds(60),
        Map.of("alg", "RS256"),
        Map.of("aud", audiences));
  }
}
