/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

/**
 * Handles the specific {@code authorization_request_not_found} OAuth2 error by redirecting to the
 * application root, allowing the user to restart the OAuth2 login flow. Other authentication
 * failures are delegated to the wrapped failure handler (default {@link
 * SimpleUrlAuthenticationFailureHandler}, which renders a 401).
 */
public final class OAuth2AuthenticationExceptionHandler implements AuthenticationFailureHandler {

  public static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE =
      "authorization_request_not_found";

  private final AuthenticationFailureHandler delegate;

  public OAuth2AuthenticationExceptionHandler() {
    this(new SimpleUrlAuthenticationFailureHandler());
  }

  public OAuth2AuthenticationExceptionHandler(final AuthenticationFailureHandler delegate) {
    this.delegate = delegate;
  }

  @Override
  public void onAuthenticationFailure(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final AuthenticationException exception)
      throws IOException, ServletException {

    if (exception instanceof final OAuth2AuthenticationException e) {
      if (e.getError() != null
          && AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE.equals(e.getError().getErrorCode())) {
        response.sendRedirect("/");
        return;
      }
    }

    delegate.onAuthenticationFailure(request, response, exception);
  }
}
