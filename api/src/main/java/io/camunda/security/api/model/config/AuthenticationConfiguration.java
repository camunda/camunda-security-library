/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcProvidersConfiguration;

/**
 * Authentication configuration bound to {@code camunda.security.authentication.*}.
 *
 * <p>This model is consumed by host applications through CSL's Spring binding and represents the
 * top-level authentication behavior switches (method selection, dev-mode API exposure, refresh
 * interval, and OIDC sub-configuration).
 */
public class AuthenticationConfiguration {

  /** Default authentication method when no explicit value is configured. */
  public static final AuthenticationMethod DEFAULT_METHOD = AuthenticationMethod.BASIC;

  /** Default for {@code camunda.security.authentication.unprotected-api}. */
  public static final boolean DEFAULT_UNPROTECTED_API = false;

  /** Authentication method. Either {@code basic} or {@code oidc}. Defaults to {@code basic}. */
  private AuthenticationMethod method = DEFAULT_METHOD;

  /**
   * When {@code true}, the API is unprotected (development mode only). Setting this disables the
   * OIDC and basic auth API protection chains in favour of a permit-all chain.
   */
  private boolean unprotectedApi = DEFAULT_UNPROTECTED_API;

  /**
   * Authentication refresh interval in ISO-8601 duration format (for example {@code PT30S}).
   *
   * <p>Used by holders that cache authentication state (for example session-based holders) to
   * decide when the cached value should be refreshed.
   */
  private String authenticationRefreshInterval = "PT30S";

  /** OIDC-specific settings (only consulted when {@code method == OIDC}). */
  private OidcConfiguration oidc = new OidcConfiguration();

  private OidcProvidersConfiguration providers;

  public AuthenticationMethod getMethod() {
    return method;
  }

  public void setMethod(final AuthenticationMethod method) {
    this.method = method;
  }

  public boolean isUnprotectedApi() {
    return unprotectedApi;
  }

  public void setUnprotectedApi(final boolean unprotectedApi) {
    this.unprotectedApi = unprotectedApi;
  }

  public String getAuthenticationRefreshInterval() {
    return authenticationRefreshInterval;
  }

  public void setAuthenticationRefreshInterval(final String authenticationRefreshInterval) {
    this.authenticationRefreshInterval = authenticationRefreshInterval;
  }

  public OidcConfiguration getOidc() {
    return oidc;
  }

  public void setOidc(final OidcConfiguration oidc) {
    this.oidc = oidc;
  }

  public OidcProvidersConfiguration getProviders() {
    return providers;
  }

  public void setProviders(final OidcProvidersConfiguration providers) {
    this.providers = providers;
  }

  /** Camunda-managed groups are disabled when OIDC is active and a groups claim is configured. */
  public boolean isCamundaGroupsEnabled() {
    return !(getMethod() == AuthenticationMethod.OIDC && getOidc().isGroupsClaimConfigured());
  }

  /** Camunda-managed users are disabled when OIDC authentication is active. */
  public boolean isCamundaUsersEnabled() {
    return getMethod() != AuthenticationMethod.OIDC;
  }
}
