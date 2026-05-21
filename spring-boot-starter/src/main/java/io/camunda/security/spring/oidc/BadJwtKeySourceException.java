/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.nimbusds.jose.KeySourceException;

/**
 * Marker {@link KeySourceException} subtype signalling that a key-source failure was caused by the
 * token itself rather than by infrastructure (e.g. unreachable JWKS endpoint, malformed JWKS
 * response).
 *
 * <p>The Nimbus key-selection contract requires throwing {@link KeySourceException}, but the same
 * exception type is reused for both client-fault failures (unknown {@code iss}, missing {@code
 * iss}, …) and server-fault failures (JWKS outage). {@link OidcAccessTokenDecoderFactory} uses this
 * marker to distinguish the two so that only the client-fault flavour is mapped to {@link
 * org.springframework.security.oauth2.jwt.BadJwtException} (and therefore HTTP 401 {@code
 * invalid_token}); generic {@link KeySourceException} keeps its default infrastructure-error
 * mapping (HTTP 500).
 */
public final class BadJwtKeySourceException extends KeySourceException {

  public BadJwtKeySourceException(final String message) {
    super(message);
  }

  public BadJwtKeySourceException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
