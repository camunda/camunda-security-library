/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.SESSION_COOKIE;

import io.camunda.security.spring.session.CamundaSessionRepositoryFilter;
import org.springframework.core.env.Environment;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Builds the Spring Session components for the default (non-scoped) webapp/API chains: a cookie
 * serializer and the {@link SessionRepositoryFilter} installed on those chains. Mirrors {@code
 * ScopedWebSessionComponentsFactory}'s approach for physical-tenant scopes (see ADR-0009).
 */
final class DefaultWebSessionComponentsFactory {

  private static final String COOKIE_NAME_PROPERTY = "server.servlet.session.cookie.name";
  private static final String COOKIE_HTTP_ONLY_PROPERTY = "server.servlet.session.cookie.http-only";
  private static final String COOKIE_SECURE_PROPERTY = "server.servlet.session.cookie.secure";
  private static final String COOKIE_SAME_SITE_PROPERTY = "server.servlet.session.cookie.same-site";
  private static final String DEFAULT_SAME_SITE = "Lax";

  private DefaultWebSessionComponentsFactory() {}

  /**
   * Builds the default cookie serializer, honouring the deployment's standard {@code
   * server.servlet.session.cookie.*} properties (name, http-only, secure, same-site). {@code
   * secure} is left to {@link DefaultCookieSerializer}'s own per-request auto-detection unless
   * explicitly configured. No basePath-scoping is applied — unlike a physical-tenant scope's
   * cookie, this one carries no {@code ContextPathScopedCookieSerializer} wrapper — but {@link
   * DefaultCookieSerializer} still scopes the cookie {@code Path} to the request's context path on
   * its own, so deployments under a non-root context path are unaffected.
   */
  static CookieSerializer cookieSerializer(final Environment environment) {
    final var cookieName = environment.getProperty(COOKIE_NAME_PROPERTY, SESSION_COOKIE);
    final var httpOnly = environment.getProperty(COOKIE_HTTP_ONLY_PROPERTY, Boolean.class, true);
    final var sameSite = environment.getProperty(COOKIE_SAME_SITE_PROPERTY, DEFAULT_SAME_SITE);
    final var secure = environment.getProperty(COOKIE_SECURE_PROPERTY, Boolean.class);

    final var serializer = new DefaultCookieSerializer();
    serializer.setCookieName(cookieName);
    serializer.setUseHttpOnlyCookie(httpOnly);
    serializer.setSameSite(sameSite);
    if (secure != null) {
      serializer.setUseSecureCookie(secure);
    }
    return serializer;
  }

  static <S extends Session> SessionRepositoryFilter<S> sessionRepositoryFilter(
      final Environment environment, final SessionRepository<S> repository) {
    final var idResolver = new CookieHttpSessionIdResolver();
    idResolver.setCookieSerializer(cookieSerializer(environment));
    final var filter = new CamundaSessionRepositoryFilter<>(repository);
    filter.setHttpSessionIdResolver(idResolver);
    return filter;
  }
}
