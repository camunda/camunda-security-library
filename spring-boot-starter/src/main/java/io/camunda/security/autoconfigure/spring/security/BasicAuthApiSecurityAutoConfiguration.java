/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.security;

import static io.camunda.security.autoconfigure.spring.security.CamundaSecurityFilterChainConstants.ORDER_WEBAPP_API;

import io.camunda.security.autoconfigure.spring.CamundaSecurityAutoConfiguration;
import io.camunda.security.autoconfigure.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.autoconfigure.spring.handler.AuthFailureHandler;
import io.camunda.security.core.adapter.SecurityPathAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.NullRequestCache;

/** Filter chain that protects API paths with HTTP Basic authentication. */
@AutoConfiguration
@AutoConfigureAfter(CamundaSecurityAutoConfiguration.class)
@Conditional(ProtectedBasicAuthApiCondition.class)
public class BasicAuthApiSecurityAutoConfiguration {

  private static final Logger LOG =
      LoggerFactory.getLogger(BasicAuthApiSecurityAutoConfiguration.class);

  @Bean
  @Order(ORDER_WEBAPP_API)
  public SecurityFilterChain basicAuthApiSecurityFilterChain(
      final HttpSecurity http,
      final AuthFailureHandler authFailureHandler,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathAdapter pathAdapter)
      throws Exception {
    LOG.info("The API is protected by HTTP Basic authentication.");
    final var filterChainBuilder =
        http.securityMatcher(pathAdapter.apiPaths().toArray(String[]::new))
            .authorizeHttpRequests(
                auth ->
                    auth.requestMatchers(pathAdapter.unprotectedApiPaths().toArray(String[]::new))
                        .permitAll()
                        .anyRequest()
                        .authenticated())
            .cors(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            .httpBasic(Customizer.withDefaults())
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(authFailureHandler)
                        .accessDeniedHandler(authFailureHandler))
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.NEVER))
            .requestCache(cache -> cache.requestCache(new NullRequestCache()));

    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathAdapter);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    return filterChainBuilder.build();
  }
}
