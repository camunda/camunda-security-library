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
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.session.web.http.SessionRepositoryFilter;

/** Builds the per-scope Spring Session components: a cookie scoped by name + Path to a basePath. */
final class ScopedWebSessionComponents {

  private ScopedWebSessionComponents() {}

  static DefaultCookieSerializer cookieSerializer(final String basePath) {
    final var serializer = new DefaultCookieSerializer();
    serializer.setCookieName(ScopedApiChainRegistrar.sessionCookieName(basePath));
    serializer.setCookiePath(basePath);
    serializer.setUseHttpOnlyCookie(true);
    serializer.setSameSite("Lax");
    return serializer;
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
