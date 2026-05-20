/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

@ExtendWith(MockitoExtension.class)
class TokenValidatorFactoryTest {

  @Mock private ClientRegistration registration;

  @BeforeEach
  void setUp() {
    // lenient — not every test consults the provider map by registration ID.
    lenient().when(registration.getRegistrationId()).thenReturn("rid");
  }

  @Test
  void shouldComposeTimestampOnlyWhenNoAudiencesOrExtras() {
    final var factory = new TokenValidatorFactory(Map.of(), Duration.ofSeconds(60), List.of());

    final var validator = factory.createTokenValidator(registration);

    assertThat(validator).isInstanceOf(DelegatingOAuth2TokenValidator.class);
    assertThat(validator.validate(validJwt()).hasErrors()).isFalse();
  }

  @Test
  void shouldIncludeAudienceValidatorWhenConfiguredForRegistration() {
    final var oidc = new OidcConfiguration();
    oidc.setAudiences(Set.of("expected-audience"));

    final var factory =
        new TokenValidatorFactory(Map.of("rid", oidc), Duration.ofSeconds(60), List.of());

    final var validator = factory.createTokenValidator(registration);

    assertThat(validator.validate(jwtWithAudience(List.of("expected-audience"))).hasErrors())
        .isFalse();
    assertThat(validator.validate(jwtWithAudience(List.of("other"))).hasErrors()).isTrue();
  }

  @Test
  void shouldSkipAudienceValidatorWhenAudiencesEmpty() {
    final var oidc = new OidcConfiguration();
    oidc.setAudiences(Set.of());

    final var factory =
        new TokenValidatorFactory(Map.of("rid", oidc), Duration.ofSeconds(60), List.of());

    // AudienceValidator throws on an empty set — factory must skip it instead of constructing.
    final var validator = factory.createTokenValidator(registration);

    assertThat(validator.validate(validJwt()).hasErrors()).isFalse();
  }

  @Test
  void shouldAppendExtraValidators() {
    final OAuth2TokenValidator<Jwt> alwaysFail =
        t -> OAuth2TokenValidatorResult.failure(new OAuth2Error("boom", "always fails", null));

    final var factory =
        new TokenValidatorFactory(Map.of(), Duration.ofSeconds(60), List.of(alwaysFail));

    final var validator = factory.createTokenValidator(registration);

    assertThat(validator.validate(validJwt()).hasErrors()).isTrue();
  }

  private static Jwt validJwt() {
    return new Jwt(
        "tv",
        Instant.now(),
        Instant.now().plusSeconds(60),
        Map.of("alg", "RS256"),
        Map.of("sub", "alice"));
  }

  private static Jwt jwtWithAudience(final List<String> audiences) {
    return new Jwt(
        "tv",
        Instant.now(),
        Instant.now().plusSeconds(60),
        Map.of("alg", "RS256"),
        Map.of("sub", "alice", "aud", audiences));
  }
}
