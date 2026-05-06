/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.PermissionType;
import io.camunda.security.api.model.ResourceType;
import io.camunda.security.core.port.in.ResourcePermissionPort;
import io.camunda.security.spring.spi.WebAppAccessDeniedHandler;
import io.camunda.security.spring.spi.WebAppProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter that enforces per-web-app authorization on webapp requests. The host plugs in:
 *
 * <ul>
 *   <li>{@link WebAppProvider} — resolves the request to a web-app id (Hub: constant, OC: derived
 *       from the URL path).
 *   <li>{@link ResourcePermissionPort} — decides whether the principal has {@code ACCESS} on the
 *       resolved web-app.
 *   <li>{@link WebAppAccessDeniedHandler} — invoked when access is denied. Hosts decide the
 *       response shape (redirect to a forbidden page, 403 JSON, RequestDispatcher.forward, etc.).
 *   <li>{@link CamundaAuthenticationProvider} — supplies the current {@link CamundaAuthentication}.
 *   <li>The set of static-resource URI suffixes the filter passes through without invoking the
 *       check (typically sourced from {@link
 *       io.camunda.security.core.port.out.SecurityPathPort#staticResourceSuffixes()}).
 * </ul>
 *
 * <p>The filter passes through without invoking the access decision when any of the following hold:
 * the request is for {@code /forbidden} (the redirect target), the request URI ends in one of the
 * configured static-resource suffixes, the principal is unauthenticated (null or anonymous), or
 * {@link WebAppProvider#webAppFor(HttpServletRequest)} returns empty.
 */
public final class WebAppAuthorizationCheckFilter extends OncePerRequestFilter {

  private static final Logger LOG = LoggerFactory.getLogger(WebAppAuthorizationCheckFilter.class);

  private static final String FORBIDDEN_PATH_SUFFIX = "/forbidden";

  private final WebAppProvider webAppProvider;
  private final ResourcePermissionPort permissionPort;
  private final WebAppAccessDeniedHandler accessDeniedHandler;
  private final CamundaAuthenticationProvider authenticationProvider;
  private final Set<String> staticResourceSuffixes;

  public WebAppAuthorizationCheckFilter(
      final WebAppProvider webAppProvider,
      final ResourcePermissionPort permissionPort,
      final WebAppAccessDeniedHandler accessDeniedHandler,
      final CamundaAuthenticationProvider authenticationProvider,
      final Set<String> staticResourceSuffixes) {
    this.webAppProvider = webAppProvider;
    this.permissionPort = permissionPort;
    this.accessDeniedHandler = accessDeniedHandler;
    this.authenticationProvider = authenticationProvider;
    this.staticResourceSuffixes = Set.copyOf(staticResourceSuffixes);
  }

  @Override
  protected void doFilterInternal(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final FilterChain filterChain)
      throws ServletException, IOException {

    if (isForbiddenPage(request) || isStaticResource(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    final CamundaAuthentication authentication = authenticationProvider.getCamundaAuthentication();
    if (authentication == null || authentication.isAnonymous()) {
      filterChain.doFilter(request, response);
      return;
    }

    final var webApp = webAppProvider.webAppFor(request);
    if (webApp.isEmpty()) {
      filterChain.doFilter(request, response);
      return;
    }

    final String resolved = webApp.get();
    if (permissionPort.hasPermission(
        authentication, ResourceType.COMPONENT, resolved, PermissionType.ACCESS)) {
      filterChain.doFilter(request, response);
      return;
    }

    LOG.debug(
        "Access denied for web app '{}' at {} (principal: {})",
        resolved,
        request.getRequestURI(),
        principalId(authentication));
    accessDeniedHandler.handle(request, response, resolved, authentication);
  }

  private static String principalId(final CamundaAuthentication authentication) {
    if (authentication.authenticatedUsername() != null) {
      return "user=" + authentication.authenticatedUsername();
    }
    if (authentication.authenticatedClientId() != null) {
      return "client=" + authentication.authenticatedClientId();
    }
    return "unknown";
  }

  private static boolean isForbiddenPage(final HttpServletRequest request) {
    return request.getRequestURI().endsWith(FORBIDDEN_PATH_SUFFIX);
  }

  private boolean isStaticResource(final HttpServletRequest request) {
    final String uri = request.getRequestURI();
    return staticResourceSuffixes.stream().anyMatch(uri::endsWith);
  }
}
