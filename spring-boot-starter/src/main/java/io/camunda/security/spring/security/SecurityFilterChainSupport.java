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
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;

import io.camunda.security.api.model.config.headers.HeaderConfiguration;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.csrf.CsrfProtectionRequestMatcher;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.header.writers.CrossOriginEmbedderPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.filter.OncePerRequestFilter;

/** Shared helpers for assembling CSL security filter chains. */
final class SecurityFilterChainSupport {

  private SecurityFilterChainSupport() {}

  static CookieCsrfTokenRepository cookieCsrfTokenRepository(
      final CamundaSecurityLibraryProperties properties) {
    final CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();
    repository.setHeaderName(X_CSRF_TOKEN);
    repository.setCookieName(X_CSRF_TOKEN);
    final boolean httpOnly = properties.getCsrf().isCookieHttpOnly();
    repository.setCookieCustomizer(builder -> builder.httpOnly(httpOnly));
    return repository;
  }

  /**
   * Applies CSRF configuration to a webapp/API filter chain. When CSRF is enabled, configures a
   * cookie-backed token repository with a {@link CsrfProtectionRequestMatcher} and adds a response
   * header filter that includes the CSRF token on authenticated GET/login responses. When disabled,
   * CSRF protection is turned off entirely.
   */
  static void applyCsrfConfiguration(
      final HttpSecurity http,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {
    if (!properties.getCsrf().isEnabled()) {
      http.csrf(AbstractHttpConfigurer::disable);
      return;
    }

    final var allowedPaths = new HashSet<String>();
    allowedPaths.addAll(pathPort.unprotectedPaths());
    allowedPaths.addAll(pathPort.unprotectedApiPaths());
    allowedPaths.add(LOGIN_URL);
    allowedPaths.add(LOGOUT_URL);
    allowedPaths.addAll(properties.getCsrf().getIgnoredPathPatterns());

    final var csrfTokenRepository = cookieCsrfTokenRepository(properties);
    http.csrf(
        csrf ->
            csrf.csrfTokenRepository(csrfTokenRepository)
                .requireCsrfProtectionMatcher(new CsrfProtectionRequestMatcher(allowedPaths)));
    http.addFilterAfter(csrfTokenResponseHeaderFilter(), CsrfFilter.class);
  }

  /**
   * Adds the filter supplied by {@code provider} after {@code afterFilter} in the chain when the
   * provider has a bean. No-op when the provider is empty, so chain configurations can opt-in to
   * library-supplied filters without hard-wiring the dependency.
   */
  static <F extends Filter> void addFilterAfterIfAvailable(
      final HttpSecurity http,
      final ObjectProvider<F> provider,
      final Class<? extends Filter> afterFilter) {
    provider.ifAvailable(filter -> http.addFilterAfter(filter, afterFilter));
  }

  /**
   * Filter that adds the CSRF token to the response header for authenticated GET requests and login
   * POST responses. Browser-based clients read the token from the response header and include it on
   * subsequent state-changing requests.
   */
  static OncePerRequestFilter csrfTokenResponseHeaderFilter() {
    return new OncePerRequestFilter() {
      @Override
      protected void doFilterInternal(
          final HttpServletRequest request,
          final HttpServletResponse response,
          final FilterChain filterChain)
          throws ServletException, IOException {
        filterChain.doFilter(request, response);
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
          return;
        }
        final String path = request.getRequestURI();
        final String method = request.getMethod();
        final boolean isGetOrLogin =
            "GET".equalsIgnoreCase(method) || (path != null && path.contains(LOGIN_URL));
        final boolean isLogout = path != null && path.contains(LOGOUT_URL);
        if (isGetOrLogin && !isLogout) {
          final CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
          if (token != null) {
            response.setHeader(X_CSRF_TOKEN, token.getToken());
          }
        }
      }
    };
  }

  /**
   * Configures HTTP security response headers from {@link HeaderConfiguration}. Each header can be
   * individually enabled/disabled and customized via {@code camunda.security.http-headers.*}.
   */
  static void setupSecureHeaders(final HttpSecurity http, final HeaderConfiguration headerConfig)
      throws Exception {
    http.headers(
        headers -> {
          if (headerConfig.getContentTypeOptions().isDisabled()) {
            headers.contentTypeOptions(c -> c.disable());
          }

          if (headerConfig.getCacheControl().isDisabled()) {
            headers.cacheControl(c -> c.disable());
          }

          final var hsts = headerConfig.getHsts();
          if (hsts.isDisabled()) {
            headers.httpStrictTransportSecurity(h -> h.disable());
          } else {
            headers.httpStrictTransportSecurity(
                h ->
                    h.includeSubDomains(hsts.isIncludeSubDomains())
                        .maxAgeInSeconds(hsts.getMaxAgeInSeconds())
                        .preload(hsts.isPreload()));
          }

          final var frame = headerConfig.getFrameOptions();
          if (frame.disabled()) {
            headers.frameOptions(f -> f.disable());
          } else {
            switch (frame.getMode()) {
              case DENY -> headers.frameOptions(f -> f.deny());
              case SAMEORIGIN -> headers.frameOptions(f -> f.sameOrigin());
              default ->
                  throw new IllegalStateException(
                      "Unhandled frame option mode: " + frame.getMode());
            }
          }

          final var csp = headerConfig.getContentSecurityPolicy();
          if (csp.isEnabled()) {
            final var policy = csp.resolvePolicy();
            if (policy != null) {
              if (csp.isReportOnly()) {
                headers.contentSecurityPolicy(c -> c.reportOnly().policyDirectives(policy));
              } else {
                headers.contentSecurityPolicy(c -> c.policyDirectives(policy));
              }
            }
          }

          headers.referrerPolicy(
              rp ->
                  rp.policy(
                      ReferrerPolicyHeaderWriter.ReferrerPolicy.valueOf(
                          headerConfig.getReferrerPolicy().getValue().name())));

          final var permissionsPolicyValue = headerConfig.getPermissionsPolicy().getValue();
          if (permissionsPolicyValue != null && !permissionsPolicyValue.isBlank()) {
            headers.permissionsPolicyHeader(pp -> pp.policy(permissionsPolicyValue));
          }

          headers.crossOriginOpenerPolicy(
              coop ->
                  coop.policy(
                      CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.valueOf(
                          headerConfig.getCrossOriginOpenerPolicy().getValue().name())));

          headers.crossOriginEmbedderPolicy(
              coep ->
                  coep.policy(
                      CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.valueOf(
                          headerConfig.getCrossOriginEmbedderPolicy().getValue().name())));

          headers.crossOriginResourcePolicy(
              corp ->
                  corp.policy(
                      CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy.valueOf(
                          headerConfig.getCrossOriginResourcePolicy().getValue().name())));
        });
  }
}
