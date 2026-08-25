/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import jakarta.servlet.http.HttpServletRequest;

/** Shared constants for the CSL security filter chains. */
public final class CamundaSecurityFilterChainConstants {

  public static final String SESSION_COOKIE = "camunda-session";
  public static final String X_CSRF_TOKEN = "X-CSRF-TOKEN";
  public static final String LOGIN_URL = "/login";
  public static final String LOGOUT_URL = "/logout";
  public static final String REDIRECT_URI = "/sso-callback";

  /**
   * The session activity-heartbeat endpoint (ADR-0023). Derived from {@code basePath} on every
   * webapp chain exactly like {@link #LOGIN_URL}/{@link #LOGOUT_URL}. A {@code POST} here is
   * recognized by {@code WebSessionRepository} as extending the session when {@code
   * camunda.security.session.heartbeat.enabled=true}; with that flag off it is a harmless 204 with
   * no special effect beyond what any other authenticated request already has.
   */
  public static final String HEARTBEAT_URL = "/session/heartbeat";

  /** Default OIDC client registration ID used by the webapp chain. */
  public static final String OIDC_REGISTRATION_ID = "oidc";

  /** Property key for {@code AuthenticationMethod} (BASIC | OIDC). */
  public static final String AUTHENTICATION_METHOD_PROPERTY =
      "camunda.security.authentication.method";

  /** Property key for the dev-mode unprotected-API toggle. */
  public static final String UNPROTECTED_API_PROPERTY =
      "camunda.security.authentication.unprotected-api";

  /** Property key for the webapp-chain activation toggle. */
  public static final String WEBAPP_ENABLED_PROPERTY =
      "camunda.security.authentication.webapp-enabled";

  public static final int ORDER_UNPROTECTED = 0;

  /**
   * The API chain (OIDC bearer or Basic auth, and the scoped API chains) sorts before the webapp
   * chain ({@link #ORDER_API} &lt; {@link #ORDER_WEBAPP}). This only matters when the two matchers
   * overlap — for hosts with disjoint API and webapp matchers (OC, Hub) the relative order has no
   * observable effect. A host whose webapp matcher is the catch-all {@code /**} (Optimize,
   * ADR-0021) relies on API-first so the API paths are claimed before the catch-all.
   */
  public static final int ORDER_API = 1;

  /** The webapp chain (and the scoped webapp chains) sorts after the API chain. */
  public static final int ORDER_WEBAPP = 2;

  public static final int ORDER_UNHANDLED = 3;

  private CamundaSecurityFilterChainConstants() {}

  /**
   * The single matching rule for what counts as a call to {@link #HEARTBEAT_URL} — a {@code POST}
   * whose path ends with that suffix. Shared by {@code WebSessionRepository} (decides whether to
   * extend session activity) and {@code SessionHeartbeatFilter} (decides whether to respond {@code
   * 204}) so the two callers can't silently drift apart on what a heartbeat request is; each wraps
   * this with its own null/exception handling for its own calling context (a servlet filter always
   * has a real request, a repository invoked from the background expiry sweep may not).
   */
  public static boolean isHeartbeatRequest(final HttpServletRequest request) {
    return request != null
        && "POST".equalsIgnoreCase(request.getMethod())
        && request.getRequestURI() != null
        && request.getRequestURI().endsWith(HEARTBEAT_URL);
  }
}
