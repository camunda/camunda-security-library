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
 * Marker {@link KeySourceException} subtype signalling that the client registration of a token's
 * issuer could not be resolved, for example because discovery could not reach the identity
 * provider. {@link OidcAccessTokenDecoderFactory} maps it to {@link
 * IdentityProviderUnavailableException}, so the answer is that the provider is unavailable and not
 * a refused credential.
 */
public final class UnresolvedProviderKeySourceException extends KeySourceException {

  public UnresolvedProviderKeySourceException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
