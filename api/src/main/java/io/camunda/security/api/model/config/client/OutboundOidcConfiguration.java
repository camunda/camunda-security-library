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
import org.jspecify.annotations.Nullable;

/**
 * OIDC client credentials settings of an outbound client. This class has no {@code toString} method
 * that shows the client secret.
 */
public final class OutboundOidcConfiguration {

  private @Nullable String tokenUri;
  private @Nullable String clientId;
  private @Nullable String clientSecret;
  private @Nullable String audience;
  private List<String> scopes = new ArrayList<>();
  private @Nullable String resource;
  private @Nullable Duration connectTimeout;
  private @Nullable Duration readTimeout;
  private @Nullable Duration requestTimeout;

  public @Nullable String getTokenUri() {
    return tokenUri;
  }

  public void setTokenUri(final @Nullable String tokenUri) {
    this.tokenUri = tokenUri;
  }

  public @Nullable String getClientId() {
    return clientId;
  }

  public void setClientId(final @Nullable String clientId) {
    this.clientId = clientId;
  }

  public @Nullable String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(final @Nullable String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public @Nullable String getAudience() {
    return audience;
  }

  public void setAudience(final @Nullable String audience) {
    this.audience = audience;
  }

  public List<String> getScopes() {
    return scopes;
  }

  public void setScopes(final @Nullable List<String> scopes) {
    this.scopes = scopes != null ? scopes : new ArrayList<>();
  }

  public @Nullable String getResource() {
    return resource;
  }

  public void setResource(final @Nullable String resource) {
    this.resource = resource;
  }

  /** The connect timeout, or {@code null} to use the client default. */
  public @Nullable Duration getConnectTimeout() {
    return connectTimeout;
  }

  public void setConnectTimeout(final @Nullable Duration connectTimeout) {
    this.connectTimeout = connectTimeout;
  }

  /** The read timeout, or {@code null} to use the client default. */
  public @Nullable Duration getReadTimeout() {
    return readTimeout;
  }

  public void setReadTimeout(final @Nullable Duration readTimeout) {
    this.readTimeout = readTimeout;
  }

  /** The longest time that a call waits for a token, or {@code null} to use the client default. */
  public @Nullable Duration getRequestTimeout() {
    return requestTimeout;
  }

  public void setRequestTimeout(final @Nullable Duration requestTimeout) {
    this.requestTimeout = requestTimeout;
  }
}
