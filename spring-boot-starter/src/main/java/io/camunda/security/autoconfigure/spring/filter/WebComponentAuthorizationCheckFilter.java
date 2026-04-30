/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.filter;

import io.camunda.security.autoconfigure.spring.spi.WebComponentAccessDeniedHandler;
import io.camunda.security.autoconfigure.spring.spi.WebComponentProvider;
import io.camunda.security.core.authorization.Authorization;
import io.camunda.security.core.authorization.CamundaAuthentication;
import io.camunda.security.core.authorization.ResourceAccess;
import io.camunda.security.core.port.in.AuthorizationPort;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter that enforces per-component authorization for webapp requests. The host plugs in:
 *
 * <ul>
 *   <li>{@link WebComponentProvider} — maps a request to a component name (Hub: constant, OC:
 *       derived from the URL path).
 *   <li>{@link AuthorizationPort} — decides whether the principal has {@code ACCESS} on the
 *       resolved component.
 *   <li>{@link WebComponentAccessDeniedHandler} — invoked when access is denied (default: redirect
 *       to {@code <contextPath>/<component>/forbidden}; hosts can return 403 JSON, etc.).
 *   <li>A {@link Supplier} that returns the current {@link CamundaAuthentication}.
 * </ul>
 *
 * <p>The filter passes through without invoking the access decision when any of the following hold:
 * the request is for {@code /forbidden} (the redirect target), the request is for a static resource
 * (CSS / JS / image), the principal is unauthenticated, or {@link
 * WebComponentProvider#componentFor(HttpServletRequest)} returns empty.
 */
public final class WebComponentAuthorizationCheckFilter extends OncePerRequestFilter {

  private static final Logger LOG =
      LoggerFactory.getLogger(WebComponentAuthorizationCheckFilter.class);

  private static final List<String> STATIC_RESOURCE_SUFFIXES =
      List.of(".css", ".js", ".js.map", ".jpg", ".png", ".woff2", ".ico", ".svg");

  private final WebComponentProvider componentProvider;
  private final AuthorizationPort authorizationPort;
  private final WebComponentAccessDeniedHandler accessDeniedHandler;
  private final Supplier<CamundaAuthentication> authenticationSupplier;

  public WebComponentAuthorizationCheckFilter(
      final WebComponentProvider componentProvider,
      final AuthorizationPort authorizationPort,
      final WebComponentAccessDeniedHandler accessDeniedHandler,
      final Supplier<CamundaAuthentication> authenticationSupplier) {
    this.componentProvider = componentProvider;
    this.authorizationPort = authorizationPort;
    this.accessDeniedHandler = accessDeniedHandler;
    this.authenticationSupplier = authenticationSupplier;
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

    final CamundaAuthentication authentication = authenticationSupplier.get();
    if (authentication == null || authentication.anonymous()) {
      filterChain.doFilter(request, response);
      return;
    }

    final Optional<String> component = componentProvider.componentFor(request);
    if (component.isEmpty()) {
      filterChain.doFilter(request, response);
      return;
    }

    final String resolved = component.get();
    final ResourceAccess access =
        authorizationPort.lookup(authentication, Authorization.componentAccess(resolved));

    if (access.allowed()) {
      filterChain.doFilter(request, response);
      return;
    }

    LOG.warn("Access denied for component '{}' at {}", resolved, request.getRequestURI());
    accessDeniedHandler.handle(request, response, resolved, authentication);
  }

  private static boolean isForbiddenPage(final HttpServletRequest request) {
    return request.getRequestURI().endsWith("/forbidden");
  }

  private static boolean isStaticResource(final HttpServletRequest request) {
    final String uri = request.getRequestURI();
    return STATIC_RESOURCE_SUFFIXES.stream().anyMatch(uri::endsWith);
  }
}
