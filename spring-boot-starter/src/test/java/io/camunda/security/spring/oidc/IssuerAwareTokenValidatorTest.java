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
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

@ExtendWith(MockitoExtension.class)
class IssuerAwareTokenValidatorTest {

  @Mock private ClientRegistration clientRegistration;
  @Mock private ProviderDetails providerDetails;

  @Test
  void shouldRejectWhenIssuerUnknown() {
    final var validator = new IssuerAwareTokenValidator(List.of(), new NoopTokenValidatorFactory());
    final var jwt = createJwtWithIssuer("unknown-issuer");

    final var result = validator.validate(jwt);

    assertThat(result.hasErrors()).isTrue();
    final var error = result.getErrors().iterator().next();
    assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
    assertThat(error.getDescription()).isEqualTo("Token issuer 'unknown-issuer' is not trusted");
  }

  @Test
  void shouldRejectWhenIssuerClaimAbsent() {
    final var validator = new IssuerAwareTokenValidator(List.of(), new NoopTokenValidatorFactory());
    final var jwt =
        new Jwt(
            "tv",
            Instant.now(),
            Instant.now().plusSeconds(60),
            Map.of("alg", "RS256"),
            Map.of("sub", "alice"));

    final var result = validator.validate(jwt);

    assertThat(result.hasErrors()).isTrue();
    final var error = result.getErrors().iterator().next();
    assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
    assertThat(error.getDescription())
        .isEqualTo("Token is missing or has a blank 'iss' (issuer) claim");
  }

  @Test
  void shouldAcceptJwtWithKnownIssuer() {
    lenient().when(providerDetails.getIssuerUri()).thenReturn("known-issuer");
    when(clientRegistration.getProviderDetails()).thenReturn(providerDetails);

    final var validator =
        new IssuerAwareTokenValidator(List.of(clientRegistration), new NoopTokenValidatorFactory());
    final var jwt = createJwtWithIssuer("known-issuer");

    assertThat(validator.validate(jwt).hasErrors()).isFalse();
  }

  @Test
  void shouldValidateASharedIssuerWithTheRulesOfItsFirstRegistrationAndWarn() {
    // given two registrations of one issuer, only the first of which accepts a token
    final var issuer = "https://shared-issuer";
    final var owner = registration("owner", issuer);
    final var loser = registration("loser", issuer);
    final var appender = attachAppender();

    try {
      // when a token of that issuer is validated
      final var validator =
          new IssuerAwareTokenValidator(
              List.of(owner, loser), new RegistrationScopedTokenValidatorFactory("owner"));
      final var result = validator.validate(createJwtWithIssuer(issuer));

      // then the rules of the first registration decide, and the operator reads whose rules
      // the validator therefore does not apply
      assertThat(result.hasErrors()).isFalse();
      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage())
                    .contains(issuer)
                    .contains("'owner' wins")
                    .contains("ignore the token validation rules of 'loser'");
              });
    } finally {
      detachAppender(appender);
    }
  }

  private static ClientRegistration registration(
      final String registrationId, final String issuerUri) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/cb")
        .authorizationUri(issuerUri + "/auth")
        .tokenUri(issuerUri + "/token")
        .jwkSetUri(issuerUri + "/jwks")
        .issuerUri(issuerUri)
        .build();
  }

  private static ListAppender<ILoggingEvent> attachAppender() {
    final var logger = (Logger) LoggerFactory.getLogger(IssuerAwareTokenValidator.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachAppender(final ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(IssuerAwareTokenValidator.class)).detachAppender(appender);
  }

  private static Jwt createJwtWithIssuer(final String issuer) {
    return new Jwt(
        "tv",
        Instant.now(),
        Instant.now().plusSeconds(60),
        Map.of("alg", "RS256"),
        Map.of("iss", issuer));
  }

  /** Accepts a token only for the registration the constructor names. */
  private static class RegistrationScopedTokenValidatorFactory extends TokenValidatorFactory {

    private final String acceptingRegistrationId;

    RegistrationScopedTokenValidatorFactory(final String acceptingRegistrationId) {
      super(Map.of(), Duration.ZERO, List.of());
      this.acceptingRegistrationId = acceptingRegistrationId;
    }

    @Override
    public OAuth2TokenValidator<Jwt> createTokenValidator(
        final ClientRegistration clientRegistration) {
      final var accepts = acceptingRegistrationId.equals(clientRegistration.getRegistrationId());
      return token ->
          accepts
              ? OAuth2TokenValidatorResult.success()
              : OAuth2TokenValidatorResult.failure(
                  new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "rejected by the loser", null));
    }
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
