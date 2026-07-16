/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_UNHANDLED;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_UNPROTECTED;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.cors.NoOpCorsConfigurationSource;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Always-on filter chains: unprotected paths (highest priority) and a catch-all deny chain (lowest
 * priority). Activates Spring Security's web security infrastructure via {@link EnableWebSecurity}.
 */
@Configuration
@EnableWebSecurity
public class BaseSecurityConfiguration {

  @Bean
  @Order(ORDER_UNPROTECTED)
  public SecurityFilterChain unprotectedPathsSecurityFilterChain(
      final HttpSecurity http,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final ObjectProvider<CorsConfigurationSource> corsSourceProvider,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
      final ObjectProvider<CspCustomizer> cspCustomizers,
      final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers)
      throws Exception {
    final var corsSource = corsSourceProvider.getIfAvailable(NoOpCorsConfigurationSource::new);
    final var filterChainBuilder =
        http.securityMatcher(pathPort.unprotectedPaths().toArray(String[]::new))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .csrf(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable);

    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());
    SecurityFilterChainSupport.applyCspCustomizers(filterChainBuilder, cspCustomizers);
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

    return filterChainBuilder.build();
  }

  @Bean
  @Order(ORDER_UNHANDLED)
  public SecurityFilterChain protectedUnhandledPathsSecurityFilterChain(
      final HttpSecurity http,
      final ObjectProvider<CorsConfigurationSource> corsSourceProvider,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers)
      throws Exception {
    final var corsSource = corsSourceProvider.getIfAvailable(NoOpCorsConfigurationSource::new);
    final var filterChainBuilder =
        http.securityMatcher("/**")
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
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable);

    // Intentional: CORS and HTTPS redirect hooks apply to the catch-all chain so that a
    // host-provided CorsConfigurationSource handles preflight OPTIONS requests even for paths that
    // don't match any other chain (otherwise a broad "/**" CORS mapping would silently miss them).
    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);

    return filterChainBuilder.build();
  }
}
