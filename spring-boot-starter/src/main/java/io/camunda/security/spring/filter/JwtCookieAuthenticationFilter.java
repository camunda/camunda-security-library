/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.spi.JwtCookieTokenPort;
import io.camunda.security.spring.spi.OidcAuthenticationEntryPoint;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates incoming requests by reading a JWT from a named cookie, validating it via the
 * host's {@link JwtCookieTokenPort}, and populating the {@link SecurityContextHolder} with a {@link
 * CamundaAuthentication}-backed {@link Authentication}.
 *
 * <p>The filter delegates to two collaborators supplied by the host:
 *
 * <ul>
 *   <li>{@link JwtCookieTokenPort} — verifies the JWT signature and expiry; returns the raw claims
 *       map.
 *   <li>{@link LazyTokenClaimsConverter} — converts the claims map to a {@link
 *       CamundaAuthentication} with lazily-resolved group, role, tenant, and mapping-rule
 *       memberships backed by a {@code MembershipPort}. Each membership field is resolved at most
 *       once on the first read.
 * </ul>
 *
 * <p>On success the {@link CamundaAuthentication} is wrapped in a {@link
 * PreAuthenticatedAuthenticationToken} and stored in the {@link SecurityContextHolder}. Downstream
 * code (e.g. {@code DefaultCamundaAuthenticationProvider}) can extract it from there.
 *
 * <p>On failure — invalid or expired JWT, or conversion error — the filter delegates to the
 * injected {@link OidcAuthenticationEntryPoint} and does not continue the chain.
 *
 * <p>Requests that already carry an authenticated (non-anonymous) {@link Authentication} in the
 * {@link SecurityContextHolder} bypass this filter entirely.
 *
 * <p>The cookie name is supplied at construction time; {@link #DEFAULT_COOKIE_NAME} is the
 * recommended default when the host does not configure a custom value.
 */
public final class JwtCookieAuthenticationFilter extends OncePerRequestFilter {

  /** Default cookie name used when the host does not supply a custom value. */
  public static final String DEFAULT_COOKIE_NAME = "X-Camunda-Authorization";

  private static final Logger LOG = LoggerFactory.getLogger(JwtCookieAuthenticationFilter.class);

  private final JwtCookieTokenPort tokenPort;
  private final LazyTokenClaimsConverter tokenClaimsConverter;
  private final OidcAuthenticationEntryPoint authenticationEntryPoint;

  public JwtCookieAuthenticationFilter(
      final JwtCookieTokenPort tokenPort,
      final LazyTokenClaimsConverter tokenClaimsConverter,
      final OidcAuthenticationEntryPoint authenticationEntryPoint) {
    this.tokenPort = tokenPort;
    this.tokenClaimsConverter = tokenClaimsConverter;
    this.authenticationEntryPoint = authenticationEntryPoint;
  }

  @Override
  protected void doFilterInternal(
      final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response,
      final @NonNull FilterChain filterChain)
      throws ServletException, IOException {

    if (isAlreadyAuthenticated()) {
      filterChain.doFilter(request, response);
      return;
    }

    final String cookieValue = extractCookie(request, tokenPort.getCookieName());
    if (cookieValue == null) {
      LOG.debug(
          "No '{}' cookie on request to {}", tokenPort.getCookieName(), request.getRequestURI());
      filterChain.doFilter(request, response);
      return;
    }

    try {
      final var claims = tokenPort.validate(cookieValue);
      final var camundaAuthentication = tokenClaimsConverter.convert(claims);
      final var authentication =
          new PreAuthenticatedAuthenticationToken(
              camundaAuthentication, null, Collections.emptyList());
      SecurityContextHolder.getContext().setAuthentication(authentication);
      LOG.debug(
          "Authenticated request via cookie '{}' (principal: {})",
          tokenPort.getCookieName(),
          camundaAuthentication.formattedPrincipal());
      filterChain.doFilter(request, response);
    } catch (final AuthenticationException ex) {
      LOG.debug(
          "Cookie token validation failed for '{}': {}",
          tokenPort.getCookieName(),
          ex.getMessage());
      SecurityContextHolder.clearContext();
      authenticationEntryPoint.commence(request, response, ex);
    }
  }

  private static boolean isAlreadyAuthenticated() {
    final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    return auth != null
        && auth.isAuthenticated()
        && !(auth instanceof AnonymousAuthenticationToken);
  }

  private static String extractCookie(final HttpServletRequest request, String cookieName) {
    final Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return null;
    }
    for (final Cookie cookie : cookies) {
      if (cookieName.equals(cookie.getName())) {
        return cookie.getValue();
      }
    }
    return null;
  }
}
