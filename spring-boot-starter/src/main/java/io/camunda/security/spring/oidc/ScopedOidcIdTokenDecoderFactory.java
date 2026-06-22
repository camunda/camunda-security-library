/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.Map;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.util.StringUtils;

/**
 * Builds a per-scope {@link JwtDecoderFactory} for the OIDC {@code id_token} consumed by a scoped
 * webapp {@code oauth2Login} chain.
 *
 * <p>Spring's {@link
 * org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer
 * OAuth2LoginConfigurer} resolves a single {@code JwtDecoderFactory<ClientRegistration>} bean from
 * the application context and applies it to <em>every</em> {@code oauth2Login} chain. When the host
 * registers such a bean whose {@code jwsAlgorithmResolver} is keyed by the cluster's {@link
 * ClientRegistration} instances (a {@code Map::get} resolver), it returns {@code null} for a scoped
 * chain's registrations — which are distinct instances built from a per-scope {@link
 * org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository}.
 * Spring then fails id_token verification with {@code missing_signature_verifier} / {@code JWS
 * Algorithm: 'null'}.
 *
 * <p>This factory binds the algorithm resolution to the scope's own provider map (keyed by
 * registrationId, defaulting to {@code RS256}) so the scoped chain verifies id_token signatures
 * against the JWK set discovered from {@code issuer-uri}, matching the cluster chain, without
 * requiring an explicit {@code jwk-set-uri}.
 */
public final class ScopedOidcIdTokenDecoderFactory
    implements JwtDecoderFactory<ClientRegistration> {

  private final OidcIdTokenDecoderFactory delegate;

  /**
   * @param providersById the scope's flattened provider map keyed by registrationId
   * @param validatorFactory the scope-specific {@link TokenValidatorFactory} used to build the
   *     id_token validators
   */
  public ScopedOidcIdTokenDecoderFactory(
      final Map<String, OidcConfiguration> providersById,
      final TokenValidatorFactory validatorFactory) {
    delegate = new OidcIdTokenDecoderFactory();
    delegate.setJwsAlgorithmResolver(registration -> resolveAlgorithm(registration, providersById));
    delegate.setJwtValidatorFactory(validatorFactory::createTokenValidator);
  }

  @Override
  public JwtDecoder createDecoder(final ClientRegistration clientRegistration) {
    return delegate.createDecoder(clientRegistration);
  }

  /**
   * Resolves the expected id_token JWS algorithm for the given registration from the scope's
   * provider configuration, defaulting to {@code RS256} when the registration is unknown or
   * declares no explicit algorithm. Never returns {@code null}: returning {@code null} is exactly
   * the failure mode this factory exists to prevent.
   */
  private static JwsAlgorithm resolveAlgorithm(
      final ClientRegistration clientRegistration,
      final Map<String, OidcConfiguration> providersById) {
    final var config = providersById.get(clientRegistration.getRegistrationId());
    final var algorithm = config != null ? config.getIdTokenAlgorithm() : null;
    if (!StringUtils.hasText(algorithm)) {
      return SignatureAlgorithm.RS256;
    }
    final var signatureAlgorithm = SignatureAlgorithm.from(algorithm);
    return signatureAlgorithm != null ? signatureAlgorithm : SignatureAlgorithm.RS256;
  }
}
