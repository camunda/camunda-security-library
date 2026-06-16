/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;

/**
 * Provides the {@link ScopedWebappSecurityChainBuilder} and {@link
 * OAuth2AuthorizedClientManagerFactory} beans unconditionally (guarded only by
 * {@code @ConditionalOnMissingBean} so that hosts can override either).
 *
 * <p>The builder is required infrastructure for per-scope webapp chain construction and must not be
 * gated on the global authentication method — a BASIC-mode cluster can still register OIDC-scoped
 * webapp chains via {@link io.camunda.security.api.context.CamundaSecurityScopeProvider}.
 */
@Configuration
public class ScopedWebappSecurityChainBuilderConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public ScopedWebappSecurityChainBuilder scopedWebappSecurityChainBuilder(
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory) {
    return new ScopedWebappSecurityChainBuilder(scopedClientRegistrationFactory);
  }

  @Bean
  @ConditionalOnMissingBean
  public OAuth2AuthorizedClientManagerFactory oauth2AuthorizedClientManagerFactory() {
    return (clientRegistrationRepository, authorizedClientRepository) -> {
      final var manager =
          new DefaultOAuth2AuthorizedClientManager(
              clientRegistrationRepository, authorizedClientRepository);
      manager.setAuthorizedClientProvider(
          OAuth2AuthorizedClientProviderBuilder.builder()
              .authorizationCode()
              .refreshToken()
              .build());
      return manager;
    };
  }
}
