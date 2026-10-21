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
  private final DecoderRouting routing;

  public DeferredJwtDecoder(final Supplier<JwtDecoder> delegateSupplier) {
    this(delegateSupplier, null);
  }

  /**
   * @param routing how the delegate routes tokens, for {@code
   *     OidcWebappClientBeansConfiguration#jwtDecoder}; {@code null} when not known
   */
  DeferredJwtDecoder(final Supplier<JwtDecoder> delegateSupplier, final DecoderRouting routing) {
    Objects.requireNonNull(delegateSupplier, "delegateSupplier must not be null");
    delegate = DeferredOidcResolution.memoizeOnSuccess(() -> build(delegateSupplier));
    this.routing = routing;
  }

  /**
   * How this decoder routes tokens, so the claim converters can route the same way; {@code null}
   * for a decoder a host builds itself.
   */
  DecoderRouting routing() {
    return routing;
  }

  @Override
  public Jwt decode(final String token) throws JwtException {
    return delegate.get().decode(token);
  }

  /**
   * Reports a failed build as {@code SupplierJwtDecoder} reports it, so the chain answers with a
   * server error and not with a refused credential.
   */
  private static JwtDecoder build(final Supplier<JwtDecoder> delegateSupplier) {
    try {
      return delegateSupplier.get();
    } catch (final RuntimeException failed) {
      throw new JwtDecoderInitializationException(
          "Failed to lazily resolve the supplied JwtDecoder instance", failed);
    }
  }
}
