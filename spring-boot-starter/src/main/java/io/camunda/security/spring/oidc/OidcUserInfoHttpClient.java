/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;

/** Calls the OIDC UserInfo endpoint using {@link HttpClient} and parses the JSON response. */
final class OidcUserInfoHttpClient implements OidcUserInfoFetcher {

  /**
   * Maximum response body size; responses larger than this are rejected to prevent heap exhaustion.
   */
  static final int MAX_BODY_BYTES = 1024 * 1024; // 1 MiB

  private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;

  OidcUserInfoHttpClient(final HttpClient httpClient, final ObjectMapper objectMapper) {
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
  }

  @Override
  public Map<String, Object> fetch(final String userInfoUri, final String bearerToken) {
    final URI uri;
    try {
      uri = URI.create(userInfoUri);
    } catch (final IllegalArgumentException e) {
      throw new OidcUserInfoFetchException("Invalid UserInfo URI: " + userInfoUri, e);
    }
    final HttpRequest request =
        HttpRequest.newBuilder()
            .uri(uri)
            .header("Authorization", "Bearer " + bearerToken)
            .header("Accept", "application/json")
            .timeout(Duration.ofSeconds(10))
            .GET()
            .build();

    final HttpResponse<byte[]> response;
    try {
      response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new OidcUserInfoFetchException(
          "Network error calling UserInfo endpoint " + userInfoUri, e);
    } catch (final IOException e) {
      throw new OidcUserInfoFetchException(
          "Network error calling UserInfo endpoint " + userInfoUri, e);
    }

    if (response.statusCode() < 200 || response.statusCode() >= 300) {
      throw new OidcUserInfoFetchException(
          "UserInfo endpoint returned HTTP " + response.statusCode() + " at " + userInfoUri);
    }

    final byte[] body = response.body();
    if (body.length > MAX_BODY_BYTES) {
      throw new OidcUserInfoFetchException(
          "UserInfo response from "
              + userInfoUri
              + " exceeds the "
              + MAX_BODY_BYTES
              + "-byte limit");
    }

    final String contentType = response.headers().firstValue("Content-Type").orElse("");
    if (contentType.toLowerCase(Locale.ROOT).startsWith("application/jwt")) {
      throw new OidcUserInfoFetchException(
          "UserInfo endpoint at "
              + userInfoUri
              + " returned a signed JWT (Content-Type: "
              + contentType
              + "); only application/json responses are supported (OIDC §5.3.2)");
    }

    try {
      return objectMapper.readValue(body, MAP_TYPE);
    } catch (final IOException e) {
      throw new OidcUserInfoFetchException(
          "Failed to parse UserInfo response from " + userInfoUri, e);
    }
  }
}
