/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.SESSION_COOKIE;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;

import io.camunda.security.spring.filter.OAuth2RefreshTokenFilter;
import io.camunda.security.spring.security.SecurityFilterChainSupport;
import java.util.Objects;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

/**
 * The collaborators an API chain needs to refresh the access token of a session-authenticated
 * caller, the same way the webapp chain does. Passing one to {@link
 * ScopedApiSecurityChainBuilder#buildOidcApiChain} installs an {@link OAuth2RefreshTokenFilter};
 * passing {@code null} leaves the chain without one.
 *
 * <p>The {@code logoutHandler} is what the refresh filter falls back to when the access token has
 * expired and cannot be renewed — it has to clear the very cookies the matching webapp chain set,
 * which is why the two static factories below exist rather than a single default.
 *
 * <p>The {@code authorizedClientRepository} does not have to be the same instance the webapp chain
 * uses: {@code HttpSessionOAuth2AuthorizedClientRepository} keeps no per-instance state and reads
 * the authorized clients from a session attribute whose name is a class-level constant, so any
 * instance sees the clients the login flow stored. See ADR-0031.
 */
public record ApiTokenRefreshSupport(
    OAuth2AuthorizedClientRepository authorizedClientRepository,
    OAuth2AuthorizedClientManager authorizedClientManager,
    LogoutHandler logoutHandler) {

  public ApiTokenRefreshSupport {
    Objects.requireNonNull(
        authorizedClientRepository, "authorizedClientRepository must not be null");
    Objects.requireNonNull(authorizedClientManager, "authorizedClientManager must not be null");
    Objects.requireNonNull(logoutHandler, "logoutHandler must not be null");
  }

  /**
   * Support for the primary (non-scoped) API chain, clearing the same unscoped cookies as the
   * primary webapp chain's logout.
   */
  public static ApiTokenRefreshSupport forPrimaryChain(
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager) {
    return new ApiTokenRefreshSupport(
        authorizedClientRepository,
        authorizedClientManager,
        new CompositeLogoutHandler(
            new CookieClearingLogoutHandler(SESSION_COOKIE, X_CSRF_TOKEN),
            new SecurityContextLogoutHandler()));
  }

  /**
   * Support for a scoped API chain, clearing the scope's own session and CSRF cookies under the
   * scope's path — an unscoped clear would leave the browser holding a cookie it keeps presenting.
   */
  public static ApiTokenRefreshSupport forScope(
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager,
      final String basePath,
      final String scopedSessionCookieName,
      final String scopedCsrfCookieName) {
    final var prefix = BasePaths.normalize(basePath, "basePath");
    return new ApiTokenRefreshSupport(
        authorizedClientRepository,
        authorizedClientManager,
        new CompositeLogoutHandler(
            SecurityFilterChainSupport.pathScopedCookieClearingLogoutHandler(
                scopedSessionCookieName, prefix),
            SecurityFilterChainSupport.pathScopedCookieClearingLogoutHandler(
                scopedCsrfCookieName, prefix),
            new SecurityContextLogoutHandler()));
  }
}
