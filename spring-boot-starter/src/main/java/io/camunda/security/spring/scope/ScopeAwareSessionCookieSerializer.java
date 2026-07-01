/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Comparator;
import java.util.List;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * A {@link CookieSerializer} that picks the session cookie name and {@code Path} per request from
 * the scope base path the request matches. It lets the <em>global</em> Spring Session filter
 * ({@code @EnableSpringHttpSession}, active only with persistent web sessions) write the same
 * per-scope cookie the scoped webapp chains expect, instead of the unscoped default {@code
 * camunda-session} at {@code Path=/}. That filter runs ahead of Spring Security's {@code
 * FilterChainProxy}, so a non-scope-aware serializer there shadows the per-scope {@link
 * org.springframework.session.web.http.SessionRepositoryFilter}s and collapses cross-scope session
 * isolation.
 *
 * <p>The request path (context path stripped) is matched against the registered base paths, longest
 * first. A match yields cookie {@code camunda-session-<sanitize(basePath)>} at {@code
 * Path=contextPath + basePath}; no match delegates verbatim to {@code clusterDelegate}, preserving
 * the deployment's configured cluster cookie (name, {@code Secure}, {@code SameSite}, …).
 *
 * <p>Thread-safe: each per-scope delegate has a fixed name; only its {@code Path} is set per
 * request, always to the same {@code contextPath + basePath} constant (cf. {@link
 * ContextPathScopedCookieSerializer}).
 */
final class ScopeAwareSessionCookieSerializer implements CookieSerializer {

  private final List<ScopeCookie> scopes;
  private final CookieSerializer clusterDelegate;

  /**
   * @param normalizedBasePaths scope base paths, already normalized (leading slash, no trailing
   *     slash, empty string for the root/cluster); empty entries are ignored
   * @param clusterDelegate serializer used verbatim for requests that match no scope (the cluster /
   *     non-scoped default)
   */
  ScopeAwareSessionCookieSerializer(
      final List<String> normalizedBasePaths, final CookieSerializer clusterDelegate) {
    this.clusterDelegate = clusterDelegate;
    this.scopes =
        normalizedBasePaths.stream()
            .filter(bp -> bp != null && !bp.isEmpty())
            .distinct()
            .sorted(Comparator.comparingInt(String::length).reversed())
            .map(ScopeCookie::new)
            .toList();
  }

  @Override
  public void writeCookieValue(final CookieValue cookieValue) {
    final var request = cookieValue.getRequest();
    final var scope = resolve(request);
    if (scope == null) {
      clusterDelegate.writeCookieValue(cookieValue);
      return;
    }
    scope.delegate.setCookiePath(request.getContextPath() + scope.basePath);
    scope.delegate.writeCookieValue(cookieValue);
  }

  @Override
  public List<String> readCookieValues(final HttpServletRequest request) {
    final var scope = resolve(request);
    return scope == null
        ? clusterDelegate.readCookieValues(request)
        : scope.delegate.readCookieValues(request);
  }

  private ScopeCookie resolve(final HttpServletRequest request) {
    final var contextPath = request.getContextPath();
    final var uri = request.getRequestURI();
    final String path =
        contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)
            ? uri.substring(contextPath.length())
            : uri;
    for (final var scope : scopes) {
      if (path.equals(scope.basePath) || path.startsWith(scope.basePath + "/")) {
        return scope;
      }
    }
    return null;
  }

  /** A single scope's fixed-name cookie delegate. */
  private static final class ScopeCookie {

    private final String basePath;
    private final DefaultCookieSerializer delegate;

    private ScopeCookie(final String basePath) {
      this.basePath = basePath;
      delegate = new DefaultCookieSerializer();
      delegate.setCookieName(ScopedSecurityChainRegistrar.sessionCookieName(basePath));
      delegate.setUseHttpOnlyCookie(true);
      delegate.setSameSite("Lax");
      // Path is set per request as contextPath + basePath (a deployment constant).
    }
  }
}
