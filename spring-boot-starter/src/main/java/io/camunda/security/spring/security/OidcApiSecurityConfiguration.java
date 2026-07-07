/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_WEBAPP_API;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.scope.ScopedApiSecurityChainBuilder;
import io.camunda.security.spring.scope.ScopedApiSecurityChainBuilderConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Filter chain that protects API paths with OIDC JWT bearer authentication.
 *
 * <p>Imports {@link ScopedApiSecurityChainBuilderConfiguration} because this chain is assembled via
 * the shared {@link ScopedApiSecurityChainBuilder}; the import keeps
 * {@code @Import(OidcApiSecurityConfiguration.class)} self-contained for hosts that wire CSL
 * configs individually. The builder bean is {@code @ConditionalOnMissingBean}, so importing it here
 * and via the {@code CamundaSecurityAutoConfiguration} umbrella is idempotent.
 */
@Configuration
@Conditional(ProtectedOidcApiCondition.class)
@Import({
  ScopedApiSecurityChainBuilderConfiguration.class,
  DefaultWebSessionFilterConfiguration.class
})
public class OidcApiSecurityConfiguration {

  private static final Logger LOG = LoggerFactory.getLogger(OidcApiSecurityConfiguration.class);

  @Bean
  @Order(ORDER_WEBAPP_API)
  public SecurityFilterChain oidcApiSecurityFilterChain(
      final HttpSecurity http,
      final ScopedApiSecurityChainBuilder builder,
      final JwtDecoder jwtDecoder,
      final SecurityPathPort pathPort,
      final SessionRepositoryFilter<?> defaultSessionRepositoryFilter)
      throws Exception {
    LOG.info("The API is protected by OIDC JWT authentication.");
    return builder.buildOidcApiChain(
        http,
        pathPort.apiPaths(),
        pathPort.unprotectedApiPaths(),
        jwtDecoder,
        defaultSessionRepositoryFilter);
  }
}
