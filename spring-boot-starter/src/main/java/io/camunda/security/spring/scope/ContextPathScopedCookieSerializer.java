/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * A {@link CookieSerializer} wrapper that prepends the servlet context path to the fixed scope base
 * path on every write. The real session isolation is provided by the per-scope cookie name; this
 * wrapper merely ensures the cookie {@code Path} is correct under any deployment context path (e.g.
 * {@code /ctx}).
 *
 * <p>The context path is only known at request time via {@code request.getContextPath()} — it is
 * not available when the delegate is constructed at {@code ApplicationContext} startup, so the path
 * cannot be fixed immutably at construction and must be set on the shared delegate per request.
 * This is safe because {@code request.getContextPath()} is a deployment constant — identical for
 * every request in a given deployment — so per-request reconfiguration of the delegate is benign.
 */
final class ContextPathScopedCookieSerializer implements CookieSerializer {

  private final DefaultCookieSerializer delegate;
  private final String basePath;

  ContextPathScopedCookieSerializer(final DefaultCookieSerializer delegate, final String basePath) {
    this.delegate = delegate;
    this.basePath = basePath;
  }

  @Override
  public void writeCookieValue(final CookieValue cookieValue) {
    // request.getContextPath() is a deployment constant — same value for every request in a given
    // deployment — so per-request reconfiguration of the shared delegate's path is benign.
    final String contextPath = cookieValue.getRequest().getContextPath();
    delegate.setCookiePath(contextPath + basePath);
    delegate.writeCookieValue(cookieValue);
  }

  @Override
  public List<String> readCookieValues(final HttpServletRequest request) {
    return delegate.readCookieValues(request);
  }
}
