/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.Objects;
import java.util.function.Supplier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderInitializationException;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * A {@link JwtDecoder} that builds its delegate at the first decode, and keeps the delegate after a
 * successful build only. A decode after a failed build therefore makes a new attempt.
 *
 * <p>Spring's {@code SupplierJwtDecoder} holds its initialization lock across the build, which is
 * why this decoder replaces it. See {@link DeferredOidcResolution#memoizeOnSuccess(Supplier)}.
 */
public final class DeferredJwtDecoder implements JwtDecoder {

  private final Supplier<JwtDecoder> delegate;

  public DeferredJwtDecoder(final Supplier<JwtDecoder> delegateSupplier) {
    Objects.requireNonNull(delegateSupplier, "delegateSupplier must not be null");
    delegate = DeferredOidcResolution.memoizeOnSuccess(() -> build(delegateSupplier));
  }

  @Override
  public Jwt decode(final String token) throws JwtException {
    return delegate.get().decode(token);
  }

  /**
   * Reports a build that failed on an outage of the provider as {@link
   * IdentityProviderUnavailableException}, so the chain answers that the provider is unavailable
   * and not with a refused credential. Any other failure is a configuration error that no retry
   * removes, so it keeps the {@link JwtDecoderInitializationException} that {@code
   * SupplierJwtDecoder} reports, and the answer stays a server error.
   */
  private static JwtDecoder build(final Supplier<JwtDecoder> delegateSupplier) {
    try {
      return delegateSupplier.get();
    } catch (final RuntimeException failed) {
      if (IdentityProviderOutage.isCausing(failed)) {
        throw new IdentityProviderUnavailableException(
            "Failed to lazily resolve the supplied JwtDecoder instance: "
                + FailureDescription.describe(failed),
            failed);
      }
      throw new JwtDecoderInitializationException(
          "Failed to lazily resolve the supplied JwtDecoder instance", failed);
    }
  }
}
