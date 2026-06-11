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
import java.util.Map;

/** Calls the OIDC UserInfo endpoint using {@link HttpClient} and parses the JSON response. */
final class OidcUserInfoHttpClient implements OidcUserInfoFetcher {

  private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;

  OidcUserInfoHttpClient(final HttpClient httpClient, final ObjectMapper objectMapper) {
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
  }

  @Override
  public Map<String, Object> fetch(final String userInfoUri, final String bearerToken) {
    final HttpRequest request =
        HttpRequest.newBuilder()
            .uri(URI.create(userInfoUri))
            .header("Authorization", "Bearer " + bearerToken)
            .header("Accept", "application/json")
            .GET()
            .build();

    final HttpResponse<String> response;
    try {
      response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
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

    try {
      return objectMapper.readValue(response.body(), MAP_TYPE);
    } catch (final IOException e) {
      throw new OidcUserInfoFetchException(
          "Failed to parse UserInfo response from " + userInfoUri, e);
    }
  }
}
