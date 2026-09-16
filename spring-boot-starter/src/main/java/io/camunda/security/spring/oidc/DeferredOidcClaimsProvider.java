/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.context.OidcClaimsProvider;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import org.springframework.util.function.SingletonSupplier;

/**
 * An {@link OidcClaimsProvider} that builds its delegate at the first claims lookup.
 *
 * <p>A provider that augments claims from UserInfo needs the UserInfo URI of each issuer, and OIDC
 * discovery resolves those URIs. The application must not make that request while it starts,
 * because an identity provider it cannot reach then stops the start. {@link SingletonSupplier}
 * keeps the delegate after a successful build only, so the next claims lookup makes a new attempt
 * after a failed one.
 */
public final class DeferredOidcClaimsProvider implements OidcClaimsProvider {

  private final Supplier<OidcClaimsProvider> delegate;
  private final String subject;

  /**
   * @param subject what the delegate resolves. A failure log names it, see {@link
   *     DeferredOidcResolution#resolve(String, Supplier)}.
   */
  public DeferredOidcClaimsProvider(
      final String subject, final Supplier<OidcClaimsProvider> delegate) {
    this.subject = Objects.requireNonNull(subject, "subject must not be null");
    this.delegate =
        SingletonSupplier.of(Objects.requireNonNull(delegate, "delegate must not be null"));
  }

  @Override
  public Map<String, Object> claimsFor(
      final Map<String, Object> jwtClaims, final String tokenValue) {
    return DeferredOidcResolution.resolve(subject, delegate).claimsFor(jwtClaims, tokenValue);
  }
}
