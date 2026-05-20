/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

class IssuerAwareTokenValidatorTest {

  @Test
  void shouldThrowExceptionWhenIssuerUnknown() {
    final var validator = new IssuerAwareTokenValidator(List.of(), new NoopTokenValidatorFactory());
    final var jwt = createJwtWithIssuer("unknown-issuer");

    final var result = validator.validate(jwt);

    assertThat(result.hasErrors()).isTrue();

    final var errors = result.getErrors();
    assertThat(errors).hasSize(1);

    final var error = errors.iterator().next();
    assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
    assertThat(error.getDescription()).isEqualTo("Token issuer 'unknown-issuer' is not trusted");
  }

  @Test
  void shouldAcceptJwtWithKnownIssuer() {
    final var providerDetails = mock(ProviderDetails.class);
    when(providerDetails.getIssuerUri()).thenReturn("known-issuer");
    final var clientRegistration = mock(ClientRegistration.class);
    when(clientRegistration.getProviderDetails()).thenReturn(providerDetails);

    final var validator =
        new IssuerAwareTokenValidator(List.of(clientRegistration), new NoopTokenValidatorFactory());
    final var jwt = createJwtWithIssuer("known-issuer");

    assertThat(validator.validate(jwt).hasErrors()).isFalse();
  }

  private static Jwt createJwtWithIssuer(final String issuer) {
    return new Jwt(
        "token-value",
        Instant.now(),
        Instant.now().plusSeconds(60),
        Map.of("alg", "RS256"),
        Map.of("iss", issuer));
  }

  private static class NoopTokenValidatorFactory extends TokenValidatorFactory {

    NoopTokenValidatorFactory() {
      super(Map.of(), Duration.ZERO, List.of());
    }

    @Override
    public OAuth2TokenValidator<Jwt> createTokenValidator(
        final ClientRegistration clientRegistration) {
      return token -> OAuth2TokenValidatorResult.success();
    }
  }
}
