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
import io.camunda.security.spring.filter.AdminUserCheckFilter;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.oidc.OidcTokenEndpointCustomizer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

/**
 * Provides the shared {@link ScopedWebappSecurityChainBuilder} bean. Resolves shared collaborators
 * as constructor arguments (mirroring {@code ScopedApiSecurityChainBuilderConfiguration}) so the
 * bean is fully wired at creation time regardless of configuration evaluation order.
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
      final ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<OAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<DefaultLoginPageGeneratingFilter> oidcLoginPickerProvider,
      final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider) {
    return new ScopedWebappSecurityChainBuilder(
        authFailureHandler,
        properties,
        pathPort,
        tokenEndpointCustomizerProvider,
        logoutSuccessHandlerProvider,
        oidcUserServiceProvider,
        authorizationRequestResolverProvider,
        webAppAuthorizationFilterProvider,
        oidcLoginPickerProvider,
        adminUserCheckFilterProvider);
  }
}
