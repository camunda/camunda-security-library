/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderInitializationException;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * A {@link JwtDecoder} that builds its delegate at the first decode, and keeps the delegate after a
 * successful build only. A decode after a failed build therefore makes a new attempt, and a
 * deployment recovers as soon as the identity provider answers again.
 *
 * <p>Spring's {@code SupplierJwtDecoder} holds its initialization lock while the supplier runs. A
 * burst of decodes for a provider the application cannot reach would then wait one discovery
 * timeout after another, and the request threads of the application would run out. This decoder
 * lets each decode make its own attempt instead. A duplicate attempt on a reachable provider costs
 * one discovery request, and the first result wins.
 */
public final class DeferredJwtDecoder implements JwtDecoder {

  private final Supplier<JwtDecoder> delegateSupplier;
  private final AtomicReference<JwtDecoder> delegate = new AtomicReference<>();

  public DeferredJwtDecoder(final Supplier<JwtDecoder> delegateSupplier) {
    this.delegateSupplier = delegateSupplier;
  }

  @Override
  public Jwt decode(final String token) throws JwtException {
    return delegate().decode(token);
  }

  private JwtDecoder delegate() {
    final var cached = delegate.get();
    if (cached != null) {
      return cached;
    }
    final var built = build();
    return delegate.compareAndSet(null, built) ? built : delegate.get();
  }

  /**
   * Builds the delegate, and reports a failed build as {@code SupplierJwtDecoder} reports it. The
   * resource-server chain therefore answers with a server error, and not with a credential it
   * refuses.
   */
  private JwtDecoder build() {
    try {
      return delegateSupplier.get();
    } catch (final RuntimeException failed) {
      throw new JwtDecoderInitializationException(
          "Failed to lazily resolve the supplied JwtDecoder instance", failed);
    }
  }
}
