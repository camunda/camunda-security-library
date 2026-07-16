/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.cors.NoOpCorsConfigurationSource;
import io.camunda.security.spring.filter.AdminUserCheckFilter;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.oidc.OidcTokenEndpointCustomizer;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory;
import io.camunda.security.spring.spi.OidcAuthenticationEntryPoint;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Provides the {@link ScopedWebappSecurityChainBuilder} and {@link
 * OAuth2AuthorizedClientManagerFactory} beans. Resolves shared collaborators as constructor
 * arguments so the builder bean is fully wired at creation time regardless of configuration
 * evaluation order. Both beans are guarded by {@code @ConditionalOnMissingBean} so hosts can
 * override either.
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
      final AuthFailureHandler authFailureHandler,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<OAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<DefaultLoginPageGeneratingFilter> oidcLoginPickerProvider,
      final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider,
      final OAuth2AuthorizedClientManagerFactory authorizedClientManagerFactory,
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory,
      final ObjectProvider<CorsConfigurationSource> corsSourceProvider,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
      final ObjectProvider<OidcAuthenticationEntryPoint> oidcAuthenticationEntryPointProvider,
      final ObjectProvider<CspCustomizer> cspCustomizers,
      final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers) {
    return new ScopedWebappSecurityChainBuilder(
        authFailureHandler,
        properties,
        pathPort,
        tokenEndpointCustomizerProvider,
        oidcUserServiceProvider,
        authorizationRequestResolverProvider,
        webAppAuthorizationFilterProvider,
        oidcLoginPickerProvider,
        adminUserCheckFilterProvider,
        authorizedClientManagerFactory,
        scopedClientRegistrationFactory,
        corsSourceProvider.getIfAvailable(NoOpCorsConfigurationSource::new),
        httpsRedirectCustomizers,
        oidcAuthenticationEntryPointProvider,
        cspCustomizers,
        securityHeadersCustomizers);
  }

  // Also declared in ScopedOidcInfrastructureConfiguration; provided here too so this configuration
  // is self-contained for hosts/tests that import it without the OIDC infrastructure config.
  // Co-presence is safe — both are @ConditionalOnMissingBean.
  @Bean
  @ConditionalOnMissingBean
  public ScopedClientRegistrationFactory scopedClientRegistrationFactory() {
    return new ScopedClientRegistrationFactory();
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
