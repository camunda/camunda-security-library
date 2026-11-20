/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Signals that a token cannot be verified because the identity provider cannot be reached. It is a
 * {@link JwtException} but not a {@code BadJwtException}, so Spring Security reports it as an
 * authentication service failure and not as a rejected credential.
 */
public final class IdentityProviderUnavailableException extends JwtException {

  public IdentityProviderUnavailableException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
