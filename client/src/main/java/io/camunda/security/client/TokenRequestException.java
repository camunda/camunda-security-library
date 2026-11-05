/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import java.io.IOException;

/**
 * The token endpoint answered with an error or an unusable response. Carries the HTTP status and
 * the OAuth {@code error} fields only, never the request, the secret or a token.
 */
public final class TokenRequestException extends IOException {

  /** {@link #getStatus()} when the token endpoint gave no response. */
  public static final int NO_RESPONSE = -1;

  private static final long serialVersionUID = 1L;

  private final int status;
  private final String error;
  private final String errorDescription;

  TokenRequestException(
      final String message,
      final int status,
      final String error,
      final String errorDescription,
      final Throwable cause) {
    super(message, cause);
    this.status = status;
    this.error = error;
    this.errorDescription = errorDescription;
  }

  /**
   * A new exception with the same status and OAuth error for a caller that waited for the token
   * request that failed, so every caller can handle the failure the same way.
   */
  TokenRequestException forWaiter(final String clientId) {
    return new TokenRequestException(
        "Token request for client '" + clientId + "' failed while this caller was waiting for it",
        status,
        error,
        errorDescription,
        this);
  }

  /** HTTP status of the token response, or {@link #NO_RESPONSE} if there was none. */
  public int getStatus() {
    return status;
  }

  /** OAuth {@code error} code from the response, or {@code null} if absent. */
  public String getError() {
    return error;
  }

  /** OAuth {@code error_description} from the response, or {@code null} if absent. */
  public String getErrorDescription() {
    return errorDescription;
  }
}
