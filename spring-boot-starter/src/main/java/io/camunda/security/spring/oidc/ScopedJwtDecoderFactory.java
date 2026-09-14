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
import java.util.Map;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.SupplierJwtDecoder;
import org.springframework.util.StringUtils;

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
   * <p>The returned decoder resolves the provider's OIDC discovery document on first token decode,
   * not here: this method runs while the security chain is being built, and an unreachable identity
   * provider must not abort the application context. {@link SupplierJwtDecoder} memoizes on success
   * only, so a failed attempt is retried on the next request. Configuration errors that need no
   * network access are still raised here, where the misconfiguration belongs.
   *
   * @param authentication the authentication configuration describing the OIDC provider(s)
   * @return a {@link JwtDecoder} ready to verify tokens from the configured providers
   * @throws IllegalStateException if the configuration contains no providers, or a provider block
   *     is incomplete
   * @throws IllegalArgumentException if the scope configures several providers and any of them sets
   *     no issuer-uri, which the issuer-aware decoder requires
   */
  public JwtDecoder buildIssuerAwareDecoder(final AuthenticationConfiguration authentication) {
    return buildIssuerAwareDecoder(authentication, null);
  }

  /**
   * As {@link #buildIssuerAwareDecoder(AuthenticationConfiguration)}, naming the scope the decoder
   * belongs to in its failure logs.
   *
   * @param scopeDescription how to refer to the scope in a log message (e.g. {@code
   *     basePath=/physical-tenants/t1}), or {@code null} for the unscoped wording
   */
  public JwtDecoder buildIssuerAwareDecoder(
      final AuthenticationConfiguration authentication, final String scopeDescription) {
    final var providers = clientRegistrationFactory.flatten(authentication);
    if (providers.isEmpty()) {
      throw new IllegalStateException(
          "Scope OIDC chain requires at least one OIDC provider, but the scope's"
              + " AuthenticationConfiguration declares none. Ensure the descriptor's"
              + " AuthenticationConfiguration carries an oidc client (oidc.client-id with issuer-uri"
              + " or explicit endpoints) or one or more providers.oidc.<id> entries.");
    }
    clientRegistrationFactory.validateWithoutLoginRoutes(providers);
    decoderFactory.validateProvidersHaveIssuer(providers);
    return new SupplierJwtDecoder(
        () ->
            DeferredOidcResolution.resolve(
                decoderSubject(providers, scopeDescription),
                () -> {
                  final var registrations =
                      clientRegistrationFactory.createWithoutLoginRoutes(providers);
                  final var validatorFactory =
                      new TokenValidatorFactory(
                          providers, OidcConfiguration.DEFAULT_CLOCK_SKEW, List.of());
                  return decoderFactory.selectAccessTokenDecoder(
                      registrations, providers, validatorFactory);
                }));
  }

  private static String decoderSubject(
      final Map<String, OidcConfiguration> providers, final String scopeDescription) {
    return "the OIDC access-token decoder"
        + (StringUtils.hasText(scopeDescription) ? " for " + scopeDescription : "")
        + " with provider(s) "
        + DeferredOidcResolution.describeProviders(providers);
  }
}
