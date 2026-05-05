/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

/** Authentication configuration bound to {@code camunda.security.authentication.*}. */
public class AuthenticationConfiguration {

  /** Authentication method. Either {@code basic} or {@code oidc}. */
  private AuthenticationMethod method;

  /**
   * When {@code true}, the API is unprotected (development mode only). Setting this disables the
   * OIDC and basic auth API protection chains in favour of a permit-all chain.
   */
  private boolean unprotectedApi = false;

  /** Authentication refresh interval (ISO-8601 duration format, e.g., "PT30S"). */
  private String authenticationRefreshInterval = "PT30S";

  /** OIDC-specific settings (only consulted when {@code method == OIDC}). */
  private OidcConfiguration oidc = new OidcConfiguration();

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
}
