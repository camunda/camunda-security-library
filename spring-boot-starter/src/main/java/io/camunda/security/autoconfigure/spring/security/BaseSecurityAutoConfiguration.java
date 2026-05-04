/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.security;

import static io.camunda.security.autoconfigure.spring.security.CamundaSecurityFilterChainConstants.ORDER_UNHANDLED;
import static io.camunda.security.autoconfigure.spring.security.CamundaSecurityFilterChainConstants.ORDER_UNPROTECTED;

import io.camunda.security.autoconfigure.spring.CamundaSecurityAutoConfiguration;
import io.camunda.security.autoconfigure.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.core.port.out.SecurityPathPort;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Always-on filter chains: unprotected paths (highest priority) and a catch-all deny chain (lowest
 * priority). Activates Spring Security's web security infrastructure via {@link EnableWebSecurity}.
 */
@AutoConfiguration
@AutoConfigureAfter(CamundaSecurityAutoConfiguration.class)
@EnableWebSecurity
public class BaseSecurityAutoConfiguration {

  @Bean
  @Order(ORDER_UNPROTECTED)
  public SecurityFilterChain unprotectedPathsSecurityFilterChain(
      final HttpSecurity http,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {
    final var filterChainBuilder =
        http.securityMatcher(pathPort.unprotectedPaths().toArray(String[]::new))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable);

    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    return filterChainBuilder.build();
  }

  @Bean
  @Order(ORDER_UNHANDLED)
  public SecurityFilterChain protectedUnhandledPathsSecurityFilterChain(final HttpSecurity http)
      throws Exception {
    return http.securityMatcher("/**")
        .authorizeHttpRequests(auth -> auth.anyRequest().denyAll())
        .exceptionHandling(
            eh ->
                eh.authenticationEntryPoint(
                        (request, response, authenticationException) ->
                            response.sendError(HttpServletResponse.SC_NOT_FOUND))
                    .accessDeniedHandler(
                        (request, response, accessDeniedException) ->
                            response.sendError(HttpServletResponse.SC_NOT_FOUND)))
        .csrf(AbstractHttpConfigurer::disable)
        .cors(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .anonymous(AbstractHttpConfigurer::disable)
        .build();
  }
}
