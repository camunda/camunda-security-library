/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

/** Thrown by {@link OidcUserInfoFetcher} on network, HTTP status, or parse failures. */
final class OidcUserInfoFetchException extends RuntimeException {

  OidcUserInfoFetchException(final String message) {
    super(message);
  }

  OidcUserInfoFetchException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
