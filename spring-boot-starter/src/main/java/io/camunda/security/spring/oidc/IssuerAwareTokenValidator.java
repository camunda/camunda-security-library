/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * A custom {@link OAuth2TokenValidator} implementation that validates a {@link Jwt} based on the
 * token's issuer claim ({@code iss}). This validator ensures that the token was issued by a trusted
 * issuer registered by the list of {@link ClientRegistration}s.
 *
 * <p>If a trusted client registration is found for the token's issuer, a corresponding validator is
 * obtained (or created) via a {@link TokenValidatorFactory}, and used to validate the token.
 *
 * <p>If the issuer is not recognized, the validation fails with an {@code invalid_token} error.
 *
 * <p>This allows support for multiple issuers in multi-tenant OIDC setups.
 *
 * <p>{@link IssuerRegistrations} resolves the registration of an issuer, so a provider that does
 * not answer fails the tokens of its own issuer only. The key selector of the same decoder shares
 * its result through that instance, so the validation of a verified token resolves nothing.
 */
public class IssuerAwareTokenValidator implements OAuth2TokenValidator<Jwt> {

  private static final Logger LOG = LoggerFactory.getLogger(IssuerAwareTokenValidator.class);
  private static final String CLAIM_ISSUER = "iss";
  private static final String OAUTH2_ERROR_DESCRIPTION = "Token issuer '%s' is not trusted";

  private final IssuerRegistrations issuerRegistrations;
  private final TokenValidatorFactory tokenValidatorFactory;
  private final Map<String, OAuth2TokenValidator<Jwt>> validators;

  public IssuerAwareTokenValidator(
      final List<ClientRegistration> clientRegistrations,
      final TokenValidatorFactory tokenValidatorFactory) {
    this(IssuerRegistrations.ofResolved(clientRegistrations), tokenValidatorFactory);
  }

  public IssuerAwareTokenValidator(
      final IssuerRegistrations issuerRegistrations,
      final TokenValidatorFactory tokenValidatorFactory) {
    this.issuerRegistrations = issuerRegistrations;
    this.tokenValidatorFactory = tokenValidatorFactory;
    validators = new ConcurrentHashMap<>();
  }

  @Override
  public OAuth2TokenValidatorResult validate(final Jwt token) {
    final var issuer = token.getClaimAsString(CLAIM_ISSUER);

    if (issuer == null || issuer.isBlank()) {
      return OAuth2TokenValidatorResult.failure(
          new OAuth2Error(
              OAuth2ErrorCodes.INVALID_TOKEN,
              "Token is missing or has a blank 'iss' (issuer) claim",
              null));
    }

    final var registration = getClientRegistrationByIssuer(issuer);

    if (registration == null) {
      return OAuth2TokenValidatorResult.failure(
          new OAuth2Error(
              OAuth2ErrorCodes.INVALID_TOKEN, OAUTH2_ERROR_DESCRIPTION.formatted(issuer), null));
    }

    return getOrCreateTokenValidator(registration).validate(token);
  }

  protected OAuth2TokenValidator<Jwt> getOrCreateTokenValidator(
      final ClientRegistration clientRegistration) {
    final var issuer = clientRegistration.getProviderDetails().getIssuerUri();
    return validators.computeIfAbsent(
        issuer, k -> tokenValidatorFactory.createTokenValidator(clientRegistration));
  }

  /**
   * @throws JwtException if the resolution of the registration fails. The token is not the reason,
   *     so this keeps the server error that the key selector of the decoder gives.
   */
  protected ClientRegistration getClientRegistrationByIssuer(final String issuer) {
    final ClientRegistration registration;
    try {
      registration = issuerRegistrations.forIssuer(issuer);
    } catch (final RuntimeException unresolved) {
      throw new JwtException(
          "Failed to resolve the client registration of issuer '%s'.".formatted(issuer),
          unresolved);
    }
    if (registration == null) {
      LOG.debug("No matching client registration found for issuer uri {}", issuer);
    }
    return registration;
  }
}
