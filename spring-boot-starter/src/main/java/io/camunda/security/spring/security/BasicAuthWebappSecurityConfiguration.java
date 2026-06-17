/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_WEBAPP_API;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Filter chain serving webapp UI paths under HTTP Basic authentication. The chain itself permits
 * all webapp requests at the request-authorization layer so the SPA shell can load for
 * unauthenticated browser navigation; authentication is then driven by the SPA against {@code
 * LOGIN_URL} (handled by the form-login configurer below). Login and logout return 204 No Content
 * with the CSRF token surfaced as a response header.
 *
 * <p>After authentication, downstream filters such as {@link
 * io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter} and {@link
 * io.camunda.security.spring.filter.AdminUserCheckFilter} still run so per-web-app permission and
 * admin-presence checks apply on every authenticated request — only the request-matcher level is
 * permissive.
 */
@Configuration
@ConditionalOnProperty(
    name = "camunda.security.authentication.method",
    havingValue = "basic",
    matchIfMissing = true)
@Import(ScopedWebappSecurityChainBuilderConfiguration.class)
public class BasicAuthWebappSecurityConfiguration {

  private static final Logger LOG =
      LoggerFactory.getLogger(BasicAuthWebappSecurityConfiguration.class);

  @Bean
  @Order(ORDER_WEBAPP_API)
  public SecurityFilterChain basicAuthWebappSecurityFilterChain(
      final HttpSecurity http, final ScopedWebappSecurityChainBuilder chainBuilder)
      throws Exception {
    LOG.info("Web Applications Login/Logout is set up with Basic Authentication.");
    return chainBuilder.buildBasicWebappChain(http);
  }
}
