/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.client;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * OIDC client credentials settings of an outbound client. This class has no {@code toString} method
 * that shows the client secret.
 */
public final class OutboundOidcConfiguration {

  private String tokenUri;
  private String clientId;
  private String clientSecret;
  private String audience;
  private List<String> scopes = new ArrayList<>();
  private String resource;
  private Duration connectTimeout;
  private Duration readTimeout;

  public String getTokenUri() {
    return tokenUri;
  }

  public void setTokenUri(final String tokenUri) {
    this.tokenUri = tokenUri;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(final String clientId) {
    this.clientId = clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(final String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public String getAudience() {
    return audience;
  }

  public void setAudience(final String audience) {
    this.audience = audience;
  }

  public List<String> getScopes() {
    return scopes;
  }

  public void setScopes(final List<String> scopes) {
    this.scopes = scopes != null ? scopes : new ArrayList<>();
  }

  public String getResource() {
    return resource;
  }

  public void setResource(final String resource) {
    this.resource = resource;
  }

  /** The connect timeout, or {@code null} to use the client default. */
  public Duration getConnectTimeout() {
    return connectTimeout;
  }

  public void setConnectTimeout(final Duration connectTimeout) {
    this.connectTimeout = connectTimeout;
  }

  /** The read timeout, or {@code null} to use the client default. */
  public Duration getReadTimeout() {
    return readTimeout;
  }

  public void setReadTimeout(final Duration readTimeout) {
    this.readTimeout = readTimeout;
  }
}
