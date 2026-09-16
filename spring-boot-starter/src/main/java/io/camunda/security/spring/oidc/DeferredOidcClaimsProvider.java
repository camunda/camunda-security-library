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

/**
 * An {@link OidcClaimsProvider} that builds its delegate at the first claims lookup, and keeps the
 * delegate after a successful build only.
 *
 * <p>The delegate needs the UserInfo URI of each issuer, which OIDC discovery resolves. That
 * request must not run while the application starts. See {@link
 * DeferredOidcResolution#memoizeOnSuccess(Supplier)}.
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
        DeferredOidcResolution.memoizeOnSuccess(
            Objects.requireNonNull(delegate, "delegate must not be null"));
  }

  @Override
  public Map<String, Object> claimsFor(
      final Map<String, Object> jwtClaims, final String tokenValue) {
    return DeferredOidcResolution.resolve(subject, delegate).claimsFor(jwtClaims, tokenValue);
  }
}
