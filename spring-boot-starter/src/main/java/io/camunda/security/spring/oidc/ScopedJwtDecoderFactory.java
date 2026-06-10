/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.List;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * Entry point for building a {@link JwtDecoder} from an {@link AuthenticationConfiguration}. Turns
 * the configuration into {@link
 * org.springframework.security.oauth2.client.registration.ClientRegistration} instances via {@link
 * ScopedClientRegistrationFactory} and selects the appropriate decoder strategy (single-issuer or
 * issuer-aware) via {@link OidcAccessTokenDecoderFactory}.
 *
 * <p>Intended for per-scope security chain construction: any component that needs to decode tokens
 * for an arbitrary authentication scope can call {@link
 * #buildIssuerAwareDecoder(AuthenticationConfiguration)} without duplicating the
 * single-vs-issuer-aware selection logic.
 */
public final class ScopedJwtDecoderFactory {

  private final ScopedClientRegistrationFactory clientRegistrationFactory;
  private final OidcAccessTokenDecoderFactory decoderFactory;

  public ScopedJwtDecoderFactory(
      final ScopedClientRegistrationFactory clientRegistrationFactory,
      final OidcAccessTokenDecoderFactory decoderFactory) {
    this.clientRegistrationFactory = clientRegistrationFactory;
    this.decoderFactory = decoderFactory;
  }

  /**
   * Builds a {@link JwtDecoder} from the given {@link AuthenticationConfiguration}. Automatically
   * selects a single-issuer decoder when the configuration contains exactly one provider, or an
   * issuer-aware decoder when it contains multiple providers.
   *
   * <p>A scope-specific {@link TokenValidatorFactory} is built from the scope's merged provider map
   * so that audience and issuer-claim validation are performed against the scope's own provider
   * configuration. This ensures that scopes sharing the same issuer but declaring different
   * audiences each validate tokens against their own audience list rather than a global
   * singleton's.
   *
   * @param authentication the authentication configuration describing the OIDC provider(s)
   * @return a {@link JwtDecoder} ready to verify tokens from the configured providers
   * @throws IllegalStateException if the configuration contains no providers
   */
  public JwtDecoder buildIssuerAwareDecoder(final AuthenticationConfiguration authentication) {
    final var providers = clientRegistrationFactory.flatten(authentication);
    final var registrations = clientRegistrationFactory.createFromProviderMap(providers);
    if (registrations.isEmpty()) {
      throw new IllegalStateException(
          "Scope OIDC chain requires at least one OIDC provider, but the scope's"
              + " AuthenticationConfiguration declares none. Ensure the descriptor's"
              + " AuthenticationConfiguration carries an oidc client (oidc.client-id with issuer-uri"
              + " or explicit endpoints) or one or more providers.oidc.<id> entries.");
    }
    final var validatorFactory =
        new TokenValidatorFactory(providers, OidcConfiguration.DEFAULT_CLOCK_SKEW, List.of());
    return decoderFactory.selectAccessTokenDecoder(registrations, providers, validatorFactory);
  }
}
