/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DeferredCsrfToken;

/**
 * A {@link CsrfTokenRepository} wrapper that prepends the servlet context path to the fixed scope
 * base path when saving the CSRF cookie. The real CSRF isolation is provided by the per-scope
 * session; this wrapper ensures the cookie {@code Path} is correct under any deployment context
 * path (e.g. {@code /ctx}).
 *
 * <p>The context path is only known at request time via {@code request.getContextPath()} — it is
 * not available when the delegate is constructed at {@code ApplicationContext} startup, so the path
 * cannot be fixed immutably at construction and must be set on the shared delegate per request.
 * This is safe because {@code request.getContextPath()} is a deployment constant — identical for
 * every request in a given deployment — so per-request reconfiguration of the delegate is benign.
 */
final class ContextPathScopedCsrfTokenRepository implements CsrfTokenRepository {

  private final CookieCsrfTokenRepository delegate;
  private final String basePath;

  ContextPathScopedCsrfTokenRepository(
      final CookieCsrfTokenRepository delegate, final String basePath) {
    this.delegate = delegate;
    this.basePath = basePath;
  }

  @Override
  public CsrfToken generateToken(final HttpServletRequest request) {
    return delegate.generateToken(request);
  }

  @Override
  public void saveToken(
      final CsrfToken token, final HttpServletRequest request, final HttpServletResponse response) {
    configureCookiePath(request);
    delegate.saveToken(token, request, response);
  }

  @Override
  public CsrfToken loadToken(final HttpServletRequest request) {
    return delegate.loadToken(request);
  }

  @Override
  public DeferredCsrfToken loadDeferredToken(
      final HttpServletRequest request, final HttpServletResponse response) {
    configureCookiePath(request);
    return delegate.loadDeferredToken(request, response);
  }

  private void configureCookiePath(final HttpServletRequest request) {
    // request.getContextPath() is a deployment constant — same value for every request in a given
    // deployment — so per-request reconfiguration of the shared delegate's path is benign.
    delegate.setCookiePath(request.getContextPath() + basePath);
  }
}
