/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.client.OutboundCredentialsProvider.StatusCode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class BasicAuthCredentialsProviderTest {

  private final BasicAuthCredentialsProvider provider =
      new BasicAuthCredentialsProvider(new BasicAuthConfiguration("demo", "p:ss"));

  @Test
  void setsBasicAuthorizationHeader() {
    final List<String> headers = new ArrayList<>();

    provider.applyCredentials((header, value) -> headers.add(header + "=" + value));

    // base64("demo:p:ss")
    assertThat(headers).containsExactly("Authorization=Basic ZGVtbzpwOnNz");
  }

  @Test
  void neverAsksForRetry() {
    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();
    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(500))).isFalse();
  }

  @Test
  void closeThroughTheInterfaceDoesNothing() throws IOException {
    final OutboundCredentialsProvider asInterface = provider;

    asInterface.close();

    final List<String> headers = new ArrayList<>();
    asInterface.applyCredentials((header, value) -> headers.add(header + "=" + value));
    assertThat(headers).containsExactly("Authorization=Basic ZGVtbzpwOnNz");
  }
}
