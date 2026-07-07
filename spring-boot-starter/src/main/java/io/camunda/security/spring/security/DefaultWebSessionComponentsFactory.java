/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.SESSION_COOKIE;

import org.springframework.core.env.Environment;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Builds the Spring Session components for the default (non-scoped) webapp/API chains, mirroring
 * {@code ScopedWebSessionComponentsFactory} so the default surface gets its session filter the same
 * way a physical-tenant scope does (ADR-0031) — no {@code @EnableSpringHttpSession}, no separately
 * registered global filter.
 */
final class DefaultWebSessionComponentsFactory {

  private static final String COOKIE_NAME_PROPERTY = "server.servlet.session.cookie.name";

  private DefaultWebSessionComponentsFactory() {}

  /**
   * Builds the default cookie serializer. The cookie name honours the deployment's configured
   * {@code server.servlet.session.cookie.name}, falling back to {@link
   * CamundaSecurityFilterChainConstants#SESSION_COOKIE} — the same property/default PR #477's
   * removed global resolver used. No path-scoping is applied: the default surface is rooted at
   * {@code /}.
   */
  static CookieSerializer cookieSerializer(final Environment environment) {
    final var cookieName = environment.getProperty(COOKIE_NAME_PROPERTY, SESSION_COOKIE);
    final var serializer = new DefaultCookieSerializer();
    serializer.setCookieName(cookieName);
    serializer.setUseHttpOnlyCookie(true);
    serializer.setSameSite("Lax");
    return serializer;
  }

  static <S extends Session> SessionRepositoryFilter<S> sessionRepositoryFilter(
      final Environment environment, final SessionRepository<S> repository) {
    final var idResolver = new CookieHttpSessionIdResolver();
    idResolver.setCookieSerializer(cookieSerializer(environment));
    final var filter = new SessionRepositoryFilter<>(repository);
    filter.setHttpSessionIdResolver(idResolver);
    return filter;
  }
}
