/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import java.net.http.HttpClient;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * Provides the per-scope OIDC infrastructure beans unconditionally, and independently of the global
 * authentication method of the cluster. A host can therefore contribute an OIDC-scoped {@link
 * io.camunda.security.api.model.config.ScopedSecurityDescriptor} whether {@code
 * camunda.security.authentication.method} is {@code oidc} or {@code basic}.
 *
 * <p>Each bean is {@link ConditionalOnMissingBean}, so a host, or the method-gated {@link
 * OidcBeansConfiguration}, can override an individual factory. The global {@link
 * OidcBeansConfiguration} declares no duplicate {@code @Bean} definition for these types.
 *
 * <p>Two beans get the global {@link TokenValidatorFactory} through an {@link ObjectProvider}:
 * {@link #oidcAccessTokenDecoderFactory(JWSKeySelectorFactory, ObjectProvider)} and {@link
 * #scopedJwtDecoderFactory}. In global OIDC mode, {@link OidcBeansConfiguration} supplies this
 * factory with the global providers. A cluster without global OIDC has no such factory. The two
 * beans then use a default without providers, with the default clock skew and without extra
 * validators. Each per-scope chain takes the issuers and audiences of its own scope. It takes the
 * clock skew and the extra validators from the global factory, if one exists.
 */
@Configuration
public class ScopedOidcInfrastructureConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public JWSKeySelectorFactory jwsKeySelectorFactory() {
    return new JWSKeySelectorFactory();
  }

  @Bean
  @ConditionalOnMissingBean
  public ScopedClientRegistrationFactory scopedClientRegistrationFactory(
      final Environment environment) {
    return new ScopedClientRegistrationFactory(
        environment.getProperty("server.servlet.context-path", ""));
  }

  /**
   * Creates an {@link OidcAccessTokenDecoderFactory} that uses either the global {@link
   * TokenValidatorFactory} (present in global OIDC mode) or a no-op default (non-OIDC cluster).
   *
   * <p>The injected {@link TokenValidatorFactory} is only used when the global {@code jwtDecoder}
   * (declared in {@link OidcBeansConfiguration}) calls {@link
   * OidcAccessTokenDecoderFactory#selectAccessTokenDecoder(java.util.List, Map)} — the 2-arg
   * overload that forwards to the singleton factory. Per-scope chains always call the 3-arg
   * overload with a scope-specific factory. That factory does not use the providers of the injected
   * factory, but it uses its clock skew and its extra validators, see {@link
   * #scopedJwtDecoderFactory}.
   */
  @Bean
  @ConditionalOnMissingBean
  public OidcAccessTokenDecoderFactory oidcAccessTokenDecoderFactory(
      final JWSKeySelectorFactory jwsKeySelectorFactory,
      final ObjectProvider<TokenValidatorFactory> globalTokenValidatorFactory) {
    final var validatorFactory =
        globalTokenValidatorFactory.getIfAvailable(
            () ->
                new TokenValidatorFactory(
                    Map.of(), OidcConfiguration.DEFAULT_CLOCK_SKEW, List.of()));
    return new OidcAccessTokenDecoderFactory(jwsKeySelectorFactory, validatorFactory);
  }

  @Bean
  @ConditionalOnMissingBean
  public ScopedJwtDecoderFactory scopedJwtDecoderFactory(
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory,
      final OidcAccessTokenDecoderFactory oidcAccessTokenDecoderFactory,
      final ObjectProvider<TokenValidatorFactory> globalTokenValidatorFactory) {
    final var hostValidatorFactory =
        globalTokenValidatorFactory.getIfAvailable(
            () ->
                new TokenValidatorFactory(
                    Map.of(), OidcConfiguration.DEFAULT_CLOCK_SKEW, List.of()));
    return new ScopedJwtDecoderFactory(
        scopedClientRegistrationFactory, oidcAccessTokenDecoderFactory, hostValidatorFactory);
  }

  /**
   * Builds a {@link ScopedOidcClaimsProviderFactory} so consumers can construct an {@link
   * io.camunda.security.api.context.OidcClaimsProvider} for an arbitrary per-scope {@link
   * io.camunda.security.api.model.config.AuthenticationConfiguration}. Always registered (mirroring
   * the sibling {@link #scopedJwtDecoderFactory}); the per-scope {@code
   * AuthenticationConfiguration} — not the cluster default — decides whether augmentation runs. The
   * global {@code oidcUserInfoHttpClient} bean is used when present (cluster-level augmentation
   * enabled); otherwise a default client is built, so a scope can enable augmentation independently
   * of the cluster default.
   */
  @Bean
  @ConditionalOnMissingBean
  public ScopedOidcClaimsProviderFactory scopedOidcClaimsProviderFactory(
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory,
      final ObjectProvider<ObjectMapper> objectMapper,
      @Qualifier("oidcUserInfoHttpClient") final ObjectProvider<HttpClient> userInfoHttpClient,
      @Autowired(required = false) final MeterRegistry meterRegistry) {
    // Reuse the global oidcUserInfoHttpClient bean when present, else build the shared default
    // client. The global bean is contributed only with cluster augmentation enabled and
    // OidcClaimsProviderConfiguration imported (not the OidcBeansConfiguration quickstart), letting
    // a scope enable augmentation independently of the cluster default.
    final HttpClient httpClient =
        userInfoHttpClient.getIfAvailable(OidcUserInfoHttpClient::defaultHttpClient);
    // A default ObjectMapper is used when no application ObjectMapper bean is present, so the
    // factory registers unconditionally even in contexts without one.
    final ObjectMapper mapper = objectMapper.getIfAvailable(ObjectMapper::new);
    return new ScopedOidcClaimsProviderFactory(
        scopedClientRegistrationFactory, httpClient, mapper, meterRegistry);
  }
}
