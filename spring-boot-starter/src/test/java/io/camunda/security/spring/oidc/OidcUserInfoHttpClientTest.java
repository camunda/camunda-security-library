/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OidcUserInfoHttpClientTest {

  @Mock private HttpClient httpClient;
  @Mock private HttpResponse<String> response;

  private OidcUserInfoHttpClient underTest;

  @BeforeEach
  void setUp() {
    underTest = new OidcUserInfoHttpClient(httpClient, new ObjectMapper());
  }

  @Test
  void returnsParsedClaimsOnSuccess() throws Exception {
    when(response.statusCode()).thenReturn(200);
    when(response.body()).thenReturn("{\"sub\":\"alice\",\"groups\":[\"eng\",\"ops\"]}");
    doReturn(response).when(httpClient).send(any(), any());

    final Map<String, Object> result =
        underTest.fetch("https://idp.example/userinfo", "bearer-token");

    assertThat(result).containsEntry("sub", "alice");
    assertThat(result).containsKey("groups");
  }

  @Test
  void throwsOnNonSuccessStatusCode() throws Exception {
    when(response.statusCode()).thenReturn(401);
    doReturn(response).when(httpClient).send(any(), any());

    assertThatThrownBy(() -> underTest.fetch("https://idp.example/userinfo", "token"))
        .isInstanceOf(OidcUserInfoFetchException.class)
        .hasMessageContaining("401");
  }

  @Test
  void throwsOn5xxStatusCode() throws Exception {
    when(response.statusCode()).thenReturn(503);
    doReturn(response).when(httpClient).send(any(), any());

    assertThatThrownBy(() -> underTest.fetch("https://idp.example/userinfo", "token"))
        .isInstanceOf(OidcUserInfoFetchException.class)
        .hasMessageContaining("503");
  }

  @Test
  void throwsOnNetworkError() throws Exception {
    when(httpClient.send(any(), any())).thenThrow(new IOException("connection refused"));

    assertThatThrownBy(() -> underTest.fetch("https://idp.example/userinfo", "token"))
        .isInstanceOf(OidcUserInfoFetchException.class)
        .hasMessageContaining("Network error");
  }

  @Test
  void throwsOnMalformedJson() throws Exception {
    when(response.statusCode()).thenReturn(200);
    when(response.body()).thenReturn("not-valid-json{{");
    doReturn(response).when(httpClient).send(any(), any());

    assertThatThrownBy(() -> underTest.fetch("https://idp.example/userinfo", "token"))
        .isInstanceOf(OidcUserInfoFetchException.class)
        .hasMessageContaining("parse");
  }
}
