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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** Settings for the OAuth2 client credentials grant ({@code client_secret_post}). */
public final class OidcClientCredentialsConfiguration {

  static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);
  // The HTTP connection takes its timeouts as an int of milliseconds.
  private static final Duration MAX_TIMEOUT = Duration.ofMillis(Integer.MAX_VALUE);

  private final URI tokenUri;
  private final String clientId;
  private final String clientSecret;
  private final String audience;
  private final List<String> scopes;
  private final String resource;
  private final Duration connectTimeout;
  private final Duration readTimeout;

  /**
   * @param tokenUri the IdP token endpoint; it must not contain user-info
   * @param clientId the client ID; it must not be blank
   * @param clientSecret the client secret; it must not be blank
   * @param audience optional {@code audience} request parameter
   * @param scopes optional scopes, sent space-joined as {@code scope}
   * @param resource optional {@code resource} request parameter, needed by some IdPs
   * @param connectTimeout connect timeout of the token request; defaults to 10 seconds
   * @param readTimeout timeout for each wait for data of the token response, not for the whole
   *     request; defaults to 10 seconds. The DNS lookup has no timeout.
   */
  public OidcClientCredentialsConfiguration(
      final URI tokenUri,
      final String clientId,
      final String clientSecret,
      final String audience,
      final List<String> scopes,
      final String resource,
      final Duration connectTimeout,
      final Duration readTimeout) {
    if (!isHttpUriWithHost(tokenUri)) {
      throw new IllegalArgumentException("tokenUri must be an absolute http or https URI");
    }
    if (tokenUri.getRawUserInfo() != null) {
      throw new IllegalArgumentException("tokenUri must not contain user-info");
    }
    ConfigurationChecks.requireText(clientId, "clientId");
    ConfigurationChecks.requireText(clientSecret, "clientSecret");
    this.tokenUri = tokenUri;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.audience = audience;
    this.scopes = copyScopes(scopes);
    this.resource = resource;
    this.connectTimeout = positiveOrDefault(connectTimeout, "connectTimeout");
    this.readTimeout = positiveOrDefault(readTimeout, "readTimeout");
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

  private static List<String> copyScopes(final List<String> scopes) {
    if (scopes == null) {
      return Collections.emptyList();
    }
    for (final String scope : scopes) {
      if (ConfigurationChecks.isBlank(scope)) {
        throw new IllegalArgumentException("scopes must not contain blank values");
      }
    }
    return Collections.unmodifiableList(new ArrayList<>(scopes));
  }

  private static boolean isHttpUriWithHost(final URI uri) {
    return uri != null
        && uri.getHost() != null
        && ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()));
  }

  private static Duration positiveOrDefault(final Duration value, final String name) {
    if (value == null) {
      return DEFAULT_TIMEOUT;
    }
    if (value.isZero() || value.isNegative()) {
      throw new IllegalArgumentException(name + " must be positive");
    }
    if (value.compareTo(MAX_TIMEOUT) > 0) {
      throw new IllegalArgumentException(
          name + " must not be longer than " + Integer.MAX_VALUE + " milliseconds");
    }
    return value;
  }

  /**
   * The token URI without query and fragment, safe for logs and messages. The URI has no user-info,
   * as the constructor rejects it. The raw path keeps its encoding, so an encoded line break stays
   * encoded.
   */
  String redactedTokenUri() {
    final String port = tokenUri.getPort() != -1 ? ":" + tokenUri.getPort() : "";
    final String path = tokenUri.getRawPath() != null ? tokenUri.getRawPath() : "";
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
        && readTimeout.equals(other.readTimeout);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        tokenUri, clientId, clientSecret, audience, scopes, resource, connectTimeout, readTimeout);
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
        + "]";
  }
}
