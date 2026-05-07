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
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.SESSION_COOKIE;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.filter.AdminUserCheckFilter;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.csrf.CsrfToken;

/**
 * Filter chain that protects webapp UI paths with form-based Basic authentication. Login and logout
 * return 204 No Content with the CSRF token surfaced as a response header.
 */
@Configuration
@ConditionalOnProperty(
    name = "camunda.security.authentication.method",
    havingValue = "basic",
    matchIfMissing = true)
public class BasicAuthWebappSecurityConfiguration {

  private static final Logger LOG =
      LoggerFactory.getLogger(BasicAuthWebappSecurityConfiguration.class);

  @Bean
  @Order(ORDER_WEBAPP_API)
  public SecurityFilterChain basicAuthWebappSecurityFilterChain(
      final HttpSecurity http,
      final AuthFailureHandler authFailureHandler,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {
    LOG.info("Web Applications Login/Logout is set up with Basic Authentication.");

    // Form-login flow needs LOGIN_URL/LOGOUT_URL reachable without auth; static UI assets the
    // host declares via SecurityPathPort.unauthenticatedWebappPaths() are also permitted.
    // Everything else under webappPaths() requires authentication so the formLogin redirect
    // fires for unauthenticated navigations.
    final var permittedPaths = new java.util.ArrayList<String>();
    permittedPaths.add(LOGIN_URL);
    permittedPaths.add(LOGOUT_URL);
    permittedPaths.addAll(pathPort.unauthenticatedWebappPaths());

    final var filterChainBuilder =
        http.securityMatcher(pathPort.webappPaths().toArray(String[]::new))
            .authorizeHttpRequests(
                auth ->
                    auth.requestMatchers(permittedPaths.toArray(String[]::new))
                        .permitAll()
                        .anyRequest()
                        .authenticated())
            .cors(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            .formLogin(
                formLogin ->
                    formLogin
                        .loginPage(LOGIN_URL)
                        .loginProcessingUrl(LOGIN_URL)
                        .failureHandler(authFailureHandler)
                        .successHandler(
                            (request, response, authentication) -> {
                              response.setStatus(HttpStatus.NO_CONTENT.value());
                              final CsrfToken token =
                                  (CsrfToken) request.getAttribute(CsrfToken.class.getName());
                              if (token != null) {
                                response.setHeader(X_CSRF_TOKEN, token.getToken());
                              }
                            }))
            .logout(
                logout ->
                    logout
                        .logoutUrl(LOGOUT_URL)
                        .logoutSuccessHandler(
                            (request, response, authentication) ->
                                response.setStatus(HttpStatus.NO_CONTENT.value()))
                        .deleteCookies(SESSION_COOKIE, X_CSRF_TOKEN))
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(authFailureHandler)
                        .accessDeniedHandler(authFailureHandler));

    // Admin-user check runs before webapp authorization so an unprovisioned system redirects to
    // the setup UI before permission checks against unrelated web apps.
    SecurityFilterChainSupport.addFilterAfterIfAvailable(
        filterChainBuilder, adminUserCheckFilterProvider, AuthorizationFilter.class);

    SecurityFilterChainSupport.addFilterAfterIfAvailable(
        filterChainBuilder, webAppAuthorizationFilterProvider, AuthorizationFilter.class);

    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathPort);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    return filterChainBuilder.build();
  }
}
