/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.converter.OidcTokenAuthenticationConverter;
import io.camunda.security.spring.converter.TokenClaimsConvertersByIssuer;
import io.camunda.security.spring.scope.ScopedCamundaAuthenticationToken;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Builds a per-scope {@code Converter<Jwt, Authentication>} that resolves a bearer token's
 * principal with <em>that scope's own</em> claim configuration, as {@link ScopedJwtDecoderFactory}
 * builds a per-scope decoder and {@link ScopedOidcClaimsProviderFactory} a per-scope claims
 * provider.
 *
 * <p>Wired into a scope's API chain via the {@code oidcAuthenticationConverterSupplier} hook of
 * {@link io.camunda.security.spring.scope.ScopedApiSecurityChainBuilder#buildScopedApiChain} (see
 * ADR-0016). Because the conversion runs inside the scope's own filter chain — where the request
 * path, and therefore the scope, is known — two scopes that share one OIDC issuer but configure
 * different claims each resolve correctly, which the single, path-unaware global issuer-keyed map
 * (ADR-0024) cannot do. See ADR-0033 and {@link ScopedCamundaAuthenticationToken}.
 *
 * <p>The produced converter runs the scope's {@link OidcTokenAuthenticationConverter} — built from
 * the scope's own {@link #buildScopePerIssuerMap per-issuer claim map}, default converter, and
 * claims provider — then carries the resulting {@code CamundaAuthentication} on a {@link
 * ScopedCamundaAuthenticationToken}. A token the scope cannot resolve still fails with the same
 * {@code invalid_token} the global path would raise, now judged by the scope's claims.
 */
public final class ScopedOidcTokenAuthenticationConverterFactory {

  private static final Logger LOG =
      LoggerFactory.getLogger(ScopedOidcTokenAuthenticationConverterFactory.class);

  private final ScopedClientRegistrationFactory clientRegistrationFactory;
  private final ScopedOidcClaimsProviderFactory claimsProviderFactory;
  private final MembershipPort membershipPort;
  private final MembershipResolutionContextPropagator contextPropagator;

  public ScopedOidcTokenAuthenticationConverterFactory(
      final ScopedClientRegistrationFactory clientRegistrationFactory,
      final ScopedOidcClaimsProviderFactory claimsProviderFactory,
      final MembershipPort membershipPort,
      final MembershipResolutionContextPropagator contextPropagator) {
    this.clientRegistrationFactory =
        Objects.requireNonNull(clientRegistrationFactory, "clientRegistrationFactory");
    this.claimsProviderFactory =
        Objects.requireNonNull(claimsProviderFactory, "claimsProviderFactory");
    this.membershipPort = Objects.requireNonNull(membershipPort, "membershipPort");
    this.contextPropagator = Objects.requireNonNull(contextPropagator, "contextPropagator");
  }

  /**
   * Builds the per-scope {@code Converter<Jwt, Authentication>}.
   *
   * @param authentication the scope's merged authentication configuration
   * @param scopeDescription a human-readable scope name for logs (e.g. {@code
   *     basePath=/physical-tenants/t1}), or {@code null} for the unscoped wording
   */
  public Converter<Jwt, Authentication> buildConverter(
      final AuthenticationConfiguration authentication, final String scopeDescription) {
    Objects.requireNonNull(authentication, "authentication must not be null");
    final var flatConfig = authentication.getOidc();
    final var defaultConverter =
        new LazyTokenClaimsConverter(
            flatConfig.getUsernameClaim(),
            flatConfig.getClientIdClaim(),
            flatConfig.isPreferUsernameClaim(),
            membershipPort,
            contextPropagator);
    final var byIssuer = buildScopePerIssuerMap(authentication, flatConfig, defaultConverter);
    final var claimsProvider =
        claimsProviderFactory.buildClaimsProvider(authentication, scopeDescription);
    final var oidcConverter =
        new OidcTokenAuthenticationConverter(
            defaultConverter, claimsProvider, new TokenClaimsConvertersByIssuer(byIssuer));
    LOG.debug(
        "Built per-scope token claims converter for {} with issuers {}",
        scopeDescription,
        byIssuer.keySet());
    // Resolve the principal with the scope's own converter and carry it on a token the global
    // converter will not re-resolve (ScopedCamundaAuthenticationToken is not a
    // JwtAuthenticationToken).
    return jwt ->
        new ScopedCamundaAuthenticationToken(
            jwt, oidcConverter.convert(new JwtAuthenticationToken(jwt)));
  }

  /**
   * Builds the scope's issuer → {@link LazyTokenClaimsConverter} map from its own providers,
   * mirroring {@code OidcBeansConfiguration#tokenClaimsConvertersByIssuer} but keyed to this scope
   * rather than the cluster. The flat block reuses {@code defaultConverter} by reference identity;
   * every other provider gets a converter from its own claim settings; providers without an {@code
   * issuer-uri} fall back to the default. {@link IssuerOwnership} picks and logs the winner when a
   * scope's own providers collide on an issuer.
   */
  private Map<String, LazyTokenClaimsConverter> buildScopePerIssuerMap(
      final AuthenticationConfiguration authentication,
      final OidcConfiguration flatConfig,
      final LazyTokenClaimsConverter defaultConverter) {
    final var configurations = clientRegistrationFactory.flatten(authentication);
    final var winningRegistrationIdByIssuer =
        IssuerOwnership.registrationIdByIssuer(
            ScopedClientRegistrationFactory.withoutBlankRegistrationIds(configurations),
            LOG,
            "the claim configuration");
    final Map<String, LazyTokenClaimsConverter> byIssuer = new LinkedHashMap<>();
    winningRegistrationIdByIssuer.forEach(
        (issuerUri, registrationId) -> {
          final var config = configurations.get(registrationId);
          final var converter =
              config == flatConfig
                  ? defaultConverter
                  : new LazyTokenClaimsConverter(
                      config.getUsernameClaim(),
                      config.getClientIdClaim(),
                      config.isPreferUsernameClaim(),
                      membershipPort,
                      contextPropagator);
          byIssuer.put(issuerUri, converter);
        });
    return byIssuer;
  }
}
