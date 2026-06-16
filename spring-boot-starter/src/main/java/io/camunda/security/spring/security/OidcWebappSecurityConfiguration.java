/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.LOGIN_URL;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.LOGOUT_URL;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_WEBAPP_API;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.REDIRECT_URI;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.oidc.OidcTokenEndpointCustomizer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

/**
 * Filter chain that protects webapp UI paths with OIDC OAuth2 login and supports session-based
 * navigation, transparent access-token refresh, and logout. The OAuth2 authorization request
 * resolver defaults to Spring Security's default; hosts that register a bean of type {@link
 * OAuth2AuthorizationRequestResolver} override that default through the {@link ObjectProvider} hook
 * on {@link #oidcWebappSecurityFilterChain}.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
public class OidcWebappSecurityConfiguration {

  @Bean
  @Order(ORDER_WEBAPP_API)
  public SecurityFilterChain oidcWebappSecurityFilterChain(
      final HttpSecurity http,
      final AuthFailureHandler authFailureHandler,
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager,
      final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
      final ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<OAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<DefaultLoginPageGeneratingFilter> oidcLoginPickerProvider,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {

    return new ScopedWebappSecurityChainBuilder()
        .buildOidcWebappChain(
            http,
            pathPort.webappPaths(),
            pathPort.unauthenticatedWebappPaths(),
            LOGIN_URL,
            LOGOUT_URL,
            REDIRECT_URI,
            authFailureHandler,
            clientRegistrationRepository,
            authorizedClientRepository,
            authorizedClientManager,
            tokenEndpointCustomizerProvider,
            logoutSuccessHandlerProvider,
            oidcUserServiceProvider,
            authorizationRequestResolverProvider,
            webAppAuthorizationFilterProvider,
            oidcLoginPickerProvider,
            properties,
            pathPort);
  }
}
