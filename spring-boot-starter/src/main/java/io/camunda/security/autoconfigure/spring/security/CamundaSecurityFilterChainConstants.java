/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.security;

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
  static final String AUTHENTICATION_METHOD_PROPERTY = "camunda.security.authentication.method";

  /** Property key for the dev-mode unprotected-API toggle. */
  static final String UNPROTECTED_API_PROPERTY = "camunda.security.authentication.unprotected-api";

  static final int ORDER_UNPROTECTED = 0;
  static final int ORDER_WEBAPP_API = 1;
  static final int ORDER_UNHANDLED = 2;

  private CamundaSecurityFilterChainConstants() {}
}
