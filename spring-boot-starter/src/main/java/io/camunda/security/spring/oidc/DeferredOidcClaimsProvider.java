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
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;

/**
 * An {@link OidcClaimsProvider} that builds its delegate at the first claims lookup, and keeps the
 * delegate after a successful build only.
 *
 * <p>The delegate needs the UserInfo URI of each issuer, which OIDC discovery resolves. That
 * request must not run while the application starts. See {@link
 * DeferredOidcResolution#memoizeOnSuccess(Supplier)}.
 *
 * <p>A lookup after a failed build throws {@link AuthenticationServiceException}, so the chain
 * answers with a server error and not with a refused credential.
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
    Objects.requireNonNull(delegate, "delegate must not be null");
    this.delegate = DeferredOidcResolution.memoizeOnSuccess(() -> build(delegate));
  }

  @Override
  public Map<String, Object> claimsFor(
      final Map<String, Object> jwtClaims, final String tokenValue) {
    return DeferredOidcResolution.resolve(subject, delegate).claimsFor(jwtClaims, tokenValue);
  }

  /**
   * Reports a failed build as a failure of the server, and not as a refused credential. Discovery
   * reports an unreachable issuer as an {@link IllegalArgumentException}, which {@link
   * io.camunda.security.spring.converter.OidcTokenAuthenticationConverter} answers with {@code
   * invalid_token}. The token is not the reason, so the build failure keeps the classification of
   * {@link AuthenticationServiceException}, which Spring Security reports as a server error, as
   * {@link DeferredJwtDecoder} does on the decoder side.
   */
  private static OidcClaimsProvider build(final Supplier<OidcClaimsProvider> delegate) {
    try {
      return delegate.get();
    } catch (final AuthenticationException alreadyClassified) {
      throw alreadyClassified;
    } catch (final RuntimeException failed) {
      throw new AuthenticationServiceException(
          "Failed to build the UserInfo claims mapping: " + failed.getMessage(), failed);
    }
  }
}
