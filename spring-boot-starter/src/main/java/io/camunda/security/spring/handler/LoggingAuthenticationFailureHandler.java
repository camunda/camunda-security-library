/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.handler;

import io.camunda.security.spring.oidc.IdentityProviderUnavailableException;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Wrapping failure handler that logs {@link AuthenticationServiceException} instances and forwards
 * them as 500 error responses, while delegating all other failures to the wrapped handler.
 */
public final class LoggingAuthenticationFailureHandler implements AuthenticationFailureHandler {

  private static final Logger LOG =
      LoggerFactory.getLogger(LoggingAuthenticationFailureHandler.class);

  private static final String IDENTITY_PROVIDER_UNAVAILABLE = "Identity provider is unavailable";

  private final AuthenticationFailureHandler delegate;

  public LoggingAuthenticationFailureHandler(final AuthenticationFailureHandler delegate) {
    this.delegate = delegate;
  }

  @Override
  public void onAuthenticationFailure(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final AuthenticationException exception)
      throws IOException, ServletException {
    if (exception.getCause() instanceof IdentityProviderUnavailableException unavailable) {
      LOG.warn(
          "{} while authenticating a bearer token: {}",
          IDENTITY_PROVIDER_UNAVAILABLE,
          rootCauseMessage(unavailable));
      response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, IDENTITY_PROVIDER_UNAVAILABLE);
      return;
    }

    // AuthenticationServiceException isn't handled by default failure handlers — without this
    // wrapper it would bubble up to Tomcat and produce a noisy ERROR log.
    if (!AuthenticationServiceException.class.isAssignableFrom(exception.getClass())) {
      delegate.onAuthenticationFailure(request, response, exception);
      return;
    }

    LOG.warn("A technical authentication problem occurred", exception);

    request.setAttribute(RequestDispatcher.ERROR_EXCEPTION, exception);
    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
  }

  private static String rootCauseMessage(final Throwable failure) {
    Throwable root = failure;
    while (root.getCause() != null && root.getCause() != root) {
      root = root.getCause();
    }
    return root.getMessage();
  }
}
