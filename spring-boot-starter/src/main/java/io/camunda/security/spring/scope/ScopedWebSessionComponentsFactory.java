/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.session.web.http.SessionRepositoryFilter;

/** Builds the per-scope Spring Session components: a cookie scoped by name + Path to a basePath. */
final class ScopedWebSessionComponentsFactory {

  private ScopedWebSessionComponentsFactory() {}

  /**
   * Builds a {@link CookieSerializer} whose cookie {@code Path} is {@code request.getContextPath()
   * + basePath} on every write. The per-scope cookie name provides the real session isolation; the
   * dynamic path ensures the browser sends the cookie under any deployment context path (e.g.
   * {@code /ctx}).
   */
  static CookieSerializer cookieSerializer(final String basePath) {
    final var normalized = BasePaths.normalize(basePath, "basePath");
    final var delegate = new DefaultCookieSerializer();
    delegate.setCookieName(ScopedSecurityChainRegistrar.sessionCookieName(basePath));
    delegate.setUseHttpOnlyCookie(true);
    delegate.setSameSite("Lax");
    // Path is NOT set on the delegate here; ContextPathScopedCookieSerializer sets it per request
    // as request.getContextPath() + basePath so the cookie is correct under any deployment context.
    return new ContextPathScopedCookieSerializer(delegate, normalized);
  }

  static <S extends Session> SessionRepositoryFilter<S> sessionRepositoryFilter(
      final String basePath, final SessionRepository<S> repository) {
    final var idResolver = new CookieHttpSessionIdResolver();
    idResolver.setCookieSerializer(cookieSerializer(basePath));
    final var filter = new SessionRepositoryFilter<>(repository);
    filter.setHttpSessionIdResolver(idResolver);
    return filter;
  }
}
