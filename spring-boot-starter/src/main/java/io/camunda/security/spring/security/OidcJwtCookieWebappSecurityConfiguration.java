/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_JWT_COOKIE_WEBAPP;

import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.filter.JwtCookieAuthenticationFilter;
import io.camunda.security.spring.spi.JwtCookieTokenPort;
import io.camunda.security.spring.spi.OidcAuthenticationEntryPoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Filter chain that protects all webapp paths with stateless JWT-cookie authentication for
 * host-specific deployments (e.g., Optimize). The chain runs at {@link
 * CamundaSecurityFilterChainConstants#ORDER_JWT_COOKIE_WEBAPP} — below the OIDC API bearer chain
 * (Order 1) — and claims every path not already claimed by a higher-priority chain via a {@code
 * /**} security matcher.
 *
 * <p>Authentication is performed by the host-registered {@link JwtCookieAuthenticationFilter}
 * (there is no library default — the host must register a complete bean). No session is created
 * ({@code STATELESS}); HTTP Basic and form login are disabled. Unauthenticated navigations are
 * handled by the configured {@link OidcAuthenticationEntryPoint}, whose default is provided by the
 * imported {@link OidcAuthenticationEntryPointConfiguration} and can be overridden by the host via
 * {@code @ConditionalOnMissingBean}.
 *
 * <p>Permitted paths (no authentication required) are the union of {@link
 * SecurityPathPort#unprotectedPaths()} and {@link SecurityPathPort#unprotectedApiPaths()}.
 *
 * <p>Activation is purely by explicit {@code @Import} — there is no {@code @ConditionalOnProperty}
 * guard and no auto-configuration entry. This chain is not part of {@code
 * CamundaSecurityAutoConfiguration}. See ADR-0008.
 *
 * <p>TODO: cross-reference ADR-0011 once it lands (GH-167).
 */
@Configuration
@Import(OidcAuthenticationEntryPointConfiguration.class)
public class OidcJwtCookieWebappSecurityConfiguration {

  @Bean
  @ConditionalOnMissingBean(name = "jwtCookieAuthenticationFilter")
  public JwtCookieAuthenticationFilter jwtCookieAuthenticationFilter(
      JwtCookieTokenPort tokenPort,
      LazyTokenClaimsConverter tokenClaimsConverter,
      OidcAuthenticationEntryPoint authenticationEntryPoint) {
    return new JwtCookieAuthenticationFilter(
        tokenPort, tokenClaimsConverter, authenticationEntryPoint);
  }

  @Bean
  @Order(ORDER_JWT_COOKIE_WEBAPP)
  @ConditionalOnMissingBean(name = "oidcJwtCookieWebappSecurityFilterChain")
  public SecurityFilterChain oidcJwtCookieWebappSecurityFilterChain(
      final HttpSecurity http,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final JwtCookieAuthenticationFilter jwtCookieAuthenticationFilter,
      final OidcAuthenticationEntryPoint authenticationEntryPoint)
      throws Exception {

    http.securityMatcher(pathPort.webappPaths().toArray(String[]::new))
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .addFilterBefore(jwtCookieAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .exceptionHandling(eh -> eh.authenticationEntryPoint(authenticationEntryPoint));

    SecurityFilterChainSupport.applyCsrfConfiguration(http, properties, pathPort);
    SecurityFilterChainSupport.setupSecureHeaders(http, properties.getHttpHeaders());

    return http.build();
  }
}
