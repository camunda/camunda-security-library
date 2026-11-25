/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Sends {@code Authorization: Basic base64(username:password)}. Never worth retrying. */
public final class BasicAuthCredentialsProvider implements OutboundCredentialsProvider {

  private final String headerValue;

  public BasicAuthCredentialsProvider(final BasicAuthConfiguration configuration) {
    final String credentials = configuration.username() + ":" + configuration.password();
    headerValue =
        "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
  }

  @Override
  public void applyCredentials(final CredentialsApplier applier) {
    applier.put("Authorization", headerValue);
  }

  @Override
  public boolean shouldRetryRequest(final StatusCode statusCode) {
    return false;
  }
}
