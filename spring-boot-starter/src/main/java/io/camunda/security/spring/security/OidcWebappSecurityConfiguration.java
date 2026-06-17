/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_WEBAPP_API;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Filter chain that protects webapp UI paths with OIDC OAuth2 login and supports session-based
 * navigation, transparent access-token refresh, and logout. The OAuth2 authorization request
 * resolver defaults to Spring Security's default; hosts that register a bean of type {@link
 * org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver} override that
 * default through the {@link org.springframework.beans.factory.ObjectProvider} hook on {@link
 * ScopedWebappSecurityChainBuilder}.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
@Import(ScopedWebappSecurityChainBuilderConfiguration.class)
public class OidcWebappSecurityConfiguration {

  @Bean
  @Order(ORDER_WEBAPP_API)
  public SecurityFilterChain oidcWebappSecurityFilterChain(
      final HttpSecurity http,
      final ScopedWebappSecurityChainBuilder chainBuilder,
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager)
      throws Exception {

    return chainBuilder.buildOidcWebappChain(
        http, clientRegistrationRepository, authorizedClientRepository, authorizedClientManager);
  }
}
