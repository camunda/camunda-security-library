/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

/** Shared constants for the CSL security filter chains. */
public final class CamundaSecurityFilterChainConstants {

  public static final String SESSION_COOKIE = "camunda-session";
  public static final String X_CSRF_TOKEN = "X-CSRF-TOKEN";
  public static final String LOGIN_URL = "/login";
  public static final String LOGOUT_URL = "/logout";
  public static final String REDIRECT_URI = "/sso-callback";

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
   * ADR-0036) relies on API-first so the API paths are claimed before the catch-all.
   */
  public static final int ORDER_API = 1;

  /** The webapp chain (and the scoped webapp chains) sorts after the API chain. */
  public static final int ORDER_WEBAPP = 2;

  public static final int ORDER_UNHANDLED = 3;

  private CamundaSecurityFilterChainConstants() {}
}
