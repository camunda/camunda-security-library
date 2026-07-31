/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.handler;

import static io.camunda.security.spring.handler.OAuth2AuthenticationExceptionHandler.AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * The {@code authorization_request_not_found} recovery redirect must land inside the application.
 * Building it with the raw servlet {@code sendRedirect} would drop the servlet context path and
 * send the user to the host root instead.
 */
@ExtendWith(MockitoExtension.class)
class OAuth2AuthenticationExceptionHandlerTest {

  @Mock private AuthenticationFailureHandler delegate;

  private final MockHttpServletResponse response = new MockHttpServletResponse();

  @Test
  void shouldRecoverToTheApplicationRootUnderAContextPath() throws Exception {
    final MockHttpServletRequest request = requestWithContextPath("/cluster-1");

    handler().onAuthenticationFailure(request, response, authorizationRequestNotFound());

    assertThat(response.getRedirectedUrl()).isEqualTo("/cluster-1/");
    verifyNoInteractions(delegate);
  }

  @Test
  void shouldRecoverToTheRootWithoutAContextPath() throws Exception {
    final MockHttpServletRequest request = requestWithContextPath("");

    handler().onAuthenticationFailure(request, response, authorizationRequestNotFound());

    assertThat(response.getRedirectedUrl()).isEqualTo("/");
    verifyNoInteractions(delegate);
  }

  @Test
  void shouldDelegateOtherOauth2Errors() throws Exception {
    final MockHttpServletRequest request = requestWithContextPath("/cluster-1");
    final AuthenticationException exception =
        new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN));

    handler().onAuthenticationFailure(request, response, exception);

    assertThat(response.getRedirectedUrl()).isNull();
    verify(delegate).onAuthenticationFailure(request, response, exception);
  }

  @Test
  void shouldDelegateNonOauth2Failures() throws Exception {
    final MockHttpServletRequest request = requestWithContextPath("/cluster-1");
    final AuthenticationException exception = new BadCredentialsException("nope");

    handler().onAuthenticationFailure(request, response, exception);

    assertThat(response.getRedirectedUrl()).isNull();
    verify(delegate).onAuthenticationFailure(request, response, exception);
  }

  private OAuth2AuthenticationExceptionHandler handler() {
    return new OAuth2AuthenticationExceptionHandler(delegate);
  }

  private static MockHttpServletRequest requestWithContextPath(final String contextPath) {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/sso-callback");
    request.setContextPath(contextPath);
    return request;
  }

  private static AuthenticationException authorizationRequestNotFound() {
    return new OAuth2AuthenticationException(
        new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE));
  }
}
