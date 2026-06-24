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

/**
 * Provides the per-scope OIDC infrastructure beans unconditionally — independently of the cluster's
 * global authentication method. This allows a host to contribute an OIDC-scoped {@link
 * io.camunda.security.api.model.config.ScopedSecurityDescriptor} regardless of whether {@code
 * camunda.security.authentication.method} is {@code oidc} or {@code basic}.
 *
 * <p>The four core factories declared here are stateless: they build from a passed {@link
 * io.camunda.security.api.model.config.AuthenticationConfiguration} rather than reading the global
 * configuration at construction time. Gating them on the global method was therefore an artificial
 * coupling. Moving them here decouples per-scope OIDC chain construction from the cluster's global
 * authentication mode. The additional {@link ScopedOidcClaimsProviderFactory} is always registered
 * (mirroring the sibling {@link ScopedJwtDecoderFactory}); the per-scope {@link
 * io.camunda.security.api.model.config.AuthenticationConfiguration} decides whether augmentation
 * runs. The global {@code oidcUserInfoHttpClient} bean is used when present; otherwise a default
 * client is built, so a scope can enable augmentation independently of the cluster default.
 *
 * <p>Each bean is {@link ConditionalOnMissingBean} so a host (or the method-gated {@link
 * OidcBeansConfiguration}) can still override individual factories. The global {@link
 * OidcBeansConfiguration} declares no duplicate {@code @Bean} definitions for these types after
 * this refactor, so there is no bean-definition collision.
 *
 * <p>The injected {@link TokenValidatorFactory} parameter on {@link
 * #oidcAccessTokenDecoderFactory(JWSKeySelectorFactory, ObjectProvider)} uses an {@link
 * ObjectProvider}: when the cluster runs in global OIDC mode, {@link OidcBeansConfiguration}
 * produces a {@link TokenValidatorFactory} seeded with the global provider configurations, and that
 * instance is injected here. When no global {@link TokenValidatorFactory} is present (non-OIDC
 * cluster), a lightweight empty-provider default is used instead. The injected factory is only used
 * by the global {@code jwtDecoder} path — per-scope chains always build a fresh scope-specific
 * {@link TokenValidatorFactory} inside {@link
 * ScopedJwtDecoderFactory#buildIssuerAwareDecoder(io.camunda.security.api.model.config.AuthenticationConfiguration)},
 * so the injected default has no effect on per-scope audience or issuer validation.
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
  public ScopedClientRegistrationFactory scopedClientRegistrationFactory() {
    return new ScopedClientRegistrationFactory();
  }

  /**
   * Creates an {@link OidcAccessTokenDecoderFactory} that uses either the global {@link
   * TokenValidatorFactory} (present in global OIDC mode) or a no-op default (non-OIDC cluster).
   *
   * <p>The injected {@link TokenValidatorFactory} is only used when the global {@code jwtDecoder}
   * (declared in {@link OidcBeansConfiguration}) calls {@link
   * OidcAccessTokenDecoderFactory#selectAccessTokenDecoder(java.util.List, Map)} — the 2-arg
   * overload that forwards to the singleton factory. Per-scope chains always call the 3-arg
   * overload with a scope-specific factory, so the injected value does not affect scope-level
   * validation.
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
      final OidcAccessTokenDecoderFactory oidcAccessTokenDecoderFactory) {
    return new ScopedJwtDecoderFactory(
        scopedClientRegistrationFactory, oidcAccessTokenDecoderFactory);
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
