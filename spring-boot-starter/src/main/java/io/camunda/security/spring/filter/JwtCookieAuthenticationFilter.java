/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.spring.converter.LazyTokenClaimsConverter;
import io.camunda.security.spring.spi.JwtCookieTokenPort;
import io.camunda.security.spring.spi.OidcAuthenticationEntryPoint;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
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
 * <p>On failure — missing cookie, invalid or expired JWT, or conversion error — the filter
 * delegates to the injected {@link OidcAuthenticationEntryPoint} and does not continue the chain.
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

  private final String cookieName;
  private final JwtCookieTokenPort tokenPort;
  private final LazyTokenClaimsConverter tokenClaimsConverter;
  private final OidcAuthenticationEntryPoint authenticationEntryPoint;

  public JwtCookieAuthenticationFilter(
      final String cookieName,
      final JwtCookieTokenPort tokenPort,
      final LazyTokenClaimsConverter tokenClaimsConverter,
      final OidcAuthenticationEntryPoint authenticationEntryPoint) {
    this.cookieName = cookieName;
    this.tokenPort = tokenPort;
    this.tokenClaimsConverter = tokenClaimsConverter;
    this.authenticationEntryPoint = authenticationEntryPoint;
  }

  @Override
  protected void doFilterInternal(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final FilterChain filterChain)
      throws ServletException, IOException {

    if (isAlreadyAuthenticated()) {
      filterChain.doFilter(request, response);
      return;
    }

    final String cookieValue = extractCookie(request);
    if (cookieValue == null) {
      LOG.debug("No '{}' cookie on request to {}", cookieName, request.getRequestURI());
      authenticationEntryPoint.commence(
          request,
          response,
          new InsufficientAuthenticationException(
              "No auth cookie '%s' found".formatted(cookieName)));
      return;
    }

    try {
      final var claims = tokenPort.validate(cookieValue);
      final var camundaAuthentication = tokenClaimsConverter.convert(claims);
      final var authentication =
          new PreAuthenticatedAuthenticationToken(camundaAuthentication, cookieValue);
      authentication.setAuthenticated(true);
      SecurityContextHolder.getContext().setAuthentication(authentication);
      LOG.debug(
          "Authenticated request via cookie '{}' (principal: {})",
          cookieName,
          principalId(camundaAuthentication));
      filterChain.doFilter(request, response);
    } catch (final AuthenticationException ex) {
      LOG.debug("Cookie token validation failed for '{}': {}", cookieName, ex.getMessage());
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

  private String extractCookie(final HttpServletRequest request) {
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

  private static String principalId(final CamundaAuthentication auth) {
    if (auth.authenticatedUsername() != null) {
      return "user=" + auth.authenticatedUsername();
    }
    if (auth.authenticatedClientId() != null) {
      return "client=" + auth.authenticatedClientId();
    }
    return "unknown";
  }
}
