/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_UNPROTECTED;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.cors.NoOpCorsConfigurationSource;
import io.camunda.security.spring.handler.AuthFailureHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Development-only filter chain that leaves all API paths unprotected. Activated when {@code
 * camunda.security.authentication.unprotected-api=true}. Never use in production.
 *
 * <p>Even though it authenticates nothing, this chain installs the shared default {@link
 * SessionRepositoryFilter} (ADR-0031) so that a web session minted on the webapp chain is resolved
 * here too. Without it, the {@code camunda-session} cookie is never read on unprotected API
 * requests and an endpoint like {@code /v2/authentication/me} would see an anonymous request even
 * for a logged-in browser. The filter only restores an existing session's {@code SecurityContext};
 * {@link SessionCreationPolicy#NEVER} keeps this chain from creating one.
 */
@Configuration
@ConditionalOnProperty(
    name = "camunda.security.authentication.unprotected-api",
    havingValue = "true")
@Import(DefaultWebSessionFilterConfiguration.class)
public class UnprotectedApiSecurityConfiguration {

  private static final Logger LOG =
      LoggerFactory.getLogger(UnprotectedApiSecurityConfiguration.class);

  @Bean
  @Order(ORDER_UNPROTECTED)
  public SecurityFilterChain unprotectedApiSecurityFilterChain(
      final HttpSecurity http,
      final AuthFailureHandler authFailureHandler,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final ObjectProvider<CorsConfigurationSource> corsSourceProvider,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
      final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers,
      final SessionRepositoryFilter<?> defaultSessionRepositoryFilter)
      throws Exception {
    LOG.warn(
        "The API is unprotected. This is intended for development only. API paths: {}",
        pathPort.apiPaths());
    // Install the shared session filter before SecurityContextHolderFilter so a session minted on
    // the webapp chain is restored here too; NEVER keeps this chain from creating one.
    http.addFilterBefore(defaultSessionRepositoryFilter, SecurityContextHolderFilter.class);
    final var corsSource = corsSourceProvider.getIfAvailable(NoOpCorsConfigurationSource::new);
    final var filterChainBuilder =
        http.securityMatcher(pathPort.apiPaths().toArray(String[]::new))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .exceptionHandling(eh -> eh.accessDeniedHandler(authFailureHandler))
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.NEVER))
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable);

    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathPort);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

    return filterChainBuilder.build();
  }
}
