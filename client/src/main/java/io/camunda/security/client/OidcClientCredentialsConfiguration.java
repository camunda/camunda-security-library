/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/** Settings for the OAuth2 client credentials grant ({@code client_secret_post}). */
public final class OidcClientCredentialsConfiguration {

  static final Duration DEFAULT_CONNECT_READ_TIMEOUT = Duration.ofSeconds(10);
  static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);

  private final URI tokenUri;
  private final String clientId;
  private final String clientSecret;
  private final String audience;
  private final List<String> scopes;
  private final String resource;
  private final Duration connectTimeout;
  private final Duration readTimeout;
  private final Duration requestTimeout;

  private OidcClientCredentialsConfiguration(final Builder builder) {
    ConfigurationChecks.requireTokenUri(builder.tokenUri, "tokenUri");
    ConfigurationChecks.requireText(builder.clientId, "clientId");
    ConfigurationChecks.requireText(builder.clientSecret, "clientSecret");
    this.tokenUri = builder.tokenUri;
    this.clientId = builder.clientId;
    this.clientSecret = builder.clientSecret;
    this.audience = ConfigurationChecks.nullIfBlank(builder.audience);
    this.scopes = ConfigurationChecks.copyNonBlank(builder.scopes, "scopes");
    this.resource = ConfigurationChecks.nullIfBlank(builder.resource);
    this.connectTimeout =
        ConfigurationChecks.positiveOrDefault(
            builder.connectTimeout, DEFAULT_CONNECT_READ_TIMEOUT, "connectTimeout");
    this.readTimeout =
        ConfigurationChecks.positiveOrDefault(
            builder.readTimeout, DEFAULT_CONNECT_READ_TIMEOUT, "readTimeout");
    this.requestTimeout =
        ConfigurationChecks.positiveOrDefault(
            builder.requestTimeout, DEFAULT_REQUEST_TIMEOUT, "requestTimeout");
  }

  /**
   * Starts a configuration. The checks run in {@link Builder#build()}.
   *
   * @param tokenUri The IdP token endpoint. It must use https. Http is allowed only for localhost,
   *     127.0.0.1 and [::1]. It must not contain user-info.
   * @param clientId The client ID. It must not be blank.
   * @param clientSecret The client secret. It must not be blank.
   * @return a new builder
   */
  public static Builder builder(
      final URI tokenUri, final String clientId, final String clientSecret) {
    return new Builder(tokenUri, clientId, clientSecret);
  }

  public URI tokenUri() {
    return tokenUri;
  }

  public String clientId() {
    return clientId;
  }

  public String clientSecret() {
    return clientSecret;
  }

  public String audience() {
    return audience;
  }

  public List<String> scopes() {
    return scopes;
  }

  public String resource() {
    return resource;
  }

  public Duration connectTimeout() {
    return connectTimeout;
  }

  public Duration readTimeout() {
    return readTimeout;
  }

  public Duration requestTimeout() {
    return requestTimeout;
  }

  /**
   * The token URI without query and fragment, safe for logs and messages. The URI has no user-info,
   * as the constructor rejects it. The raw path keeps its encoding, so an encoded line break stays
   * encoded.
   */
  String redactedTokenUri() {
    final String port = tokenUri.getPort() != -1 ? ":" + tokenUri.getPort() : "";
    final String path = tokenUri.getRawPath();
    return tokenUri.getScheme() + "://" + tokenUri.getHost() + port + path;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof OidcClientCredentialsConfiguration)) {
      return false;
    }
    final OidcClientCredentialsConfiguration other = (OidcClientCredentialsConfiguration) o;
    return tokenUri.equals(other.tokenUri)
        && clientId.equals(other.clientId)
        && clientSecret.equals(other.clientSecret)
        && Objects.equals(audience, other.audience)
        && scopes.equals(other.scopes)
        && Objects.equals(resource, other.resource)
        && connectTimeout.equals(other.connectTimeout)
        && readTimeout.equals(other.readTimeout)
        && requestTimeout.equals(other.requestTimeout);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        tokenUri,
        clientId,
        clientSecret,
        audience,
        scopes,
        resource,
        connectTimeout,
        readTimeout,
        requestTimeout);
  }

  @Override
  public String toString() {
    return "OidcClientCredentialsConfiguration[tokenUri="
        + redactedTokenUri()
        + ", clientId="
        + clientId
        + ", clientSecret=***, audience="
        + audience
        + ", scopes="
        + scopes
        + ", resource="
        + resource
        + ", connectTimeout="
        + connectTimeout
        + ", readTimeout="
        + readTimeout
        + ", requestTimeout="
        + requestTimeout
        + "]";
  }

  /** Builds an {@link OidcClientCredentialsConfiguration}. An optional setter accepts null. */
  public static final class Builder {

    private final URI tokenUri;
    private final String clientId;
    private final String clientSecret;
    private String audience;
    private List<String> scopes;
    private String resource;
    private Duration connectTimeout;
    private Duration readTimeout;
    private Duration requestTimeout;

    private Builder(final URI tokenUri, final String clientId, final String clientSecret) {
      this.tokenUri = tokenUri;
      this.clientId = clientId;
      this.clientSecret = clientSecret;
    }

    /**
     * Sets the {@code audience} request parameter. A blank value or null sends no audience.
     *
     * @param audience The audience.
     * @return this builder
     */
    public Builder audience(final String audience) {
      this.audience = audience;
      return this;
    }

    /**
     * Sets the scopes. The request sends them space-joined as {@code scope}. The build copies the
     * list. A blank scope is an error. Null gives no scopes.
     *
     * @param scopes The scopes.
     * @return this builder
     */
    public Builder scopes(final List<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    /**
     * Sets the {@code resource} request parameter. Some IdPs need it. A blank value or null sends
     * no resource.
     *
     * @param resource The resource.
     * @return this builder
     */
    public Builder resource(final String resource) {
      this.resource = resource;
      return this;
    }

    /**
     * Sets the connect timeout of the token request. Null keeps the default of 10 seconds.
     *
     * @param connectTimeout The connect timeout. It must be positive.
     * @return this builder
     */
    public Builder connectTimeout(final Duration connectTimeout) {
      this.connectTimeout = connectTimeout;
      return this;
    }

    /**
     * Sets the timeout for each wait for data of the token response. It is not the timeout of the
     * whole request. The DNS lookup has no timeout. Null keeps the default of 10 seconds.
     *
     * @param readTimeout The read timeout. It must be positive.
     * @return this builder
     */
    public Builder readTimeout(final Duration readTimeout) {
      this.readTimeout = readTimeout;
      return this;
    }

    /**
     * Sets the longest time that a call waits for a token. The wait for the token request of
     * another caller counts. Null keeps the default of 30 seconds.
     *
     * @param requestTimeout The request timeout. It must be positive.
     * @return this builder
     */
    public Builder requestTimeout(final Duration requestTimeout) {
      this.requestTimeout = requestTimeout;
      return this;
    }

    /**
     * Checks the values and creates the configuration.
     *
     * @return the configuration
     * @throws IllegalArgumentException if a value is not valid
     */
    public OidcClientCredentialsConfiguration build() {
      return new OidcClientCredentialsConfiguration(this);
    }
  }
}
