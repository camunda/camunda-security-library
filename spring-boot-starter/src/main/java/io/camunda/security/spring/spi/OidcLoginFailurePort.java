/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.spi;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import org.springframework.security.core.AuthenticationException;

/**
 * Explains a failed OIDC browser login in the host's own words. The OIDC webapp chains built by
 * {@link io.camunda.security.spring.security.ScopedWebappSecurityChainBuilder} render a small HTML
 * page when a browser login fails; when a bean of this type is present, the chains ask it first and
 * show its {@link OidcLoginFailureNotice} instead of the library's generic text.
 *
 * <p>Hosts typically recognise failures raised by their own token validators: an ID token that
 * fails validation reaches the page as an {@code OAuth2AuthenticationException} whose cause is a
 * {@code JwtValidationException}, and {@code JwtValidationException#getErrors()} carries the {@code
 * OAuth2Error} the host's validator returned.
 *
 * <p>Return {@link Optional#empty()} for failures the host has nothing to say about. The method
 * must not throw; if it does, the chain logs the failure and shows the generic page. See ADR-0035.
 */
@FunctionalInterface
public interface OidcLoginFailurePort {

  Optional<OidcLoginFailureNotice> explain(
      HttpServletRequest request, AuthenticationException exception);
}
