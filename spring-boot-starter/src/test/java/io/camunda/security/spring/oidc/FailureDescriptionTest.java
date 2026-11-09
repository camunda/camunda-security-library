/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.ConnectException;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.client.ResourceAccessException;

class FailureDescriptionTest {

  @Test
  void shouldNameTheChainAndTheOAuth2ErrorCodeButNoMessage() {
    final var failure =
        new OAuth2AuthorizationException(
            new OAuth2Error("invalid_token_response", "echoed request data", null),
            "I/O error on POST request for \"https://client:s3cret@idp.example.com/token\"",
            new ResourceAccessException(
                "I/O error on POST request for \"https://client:s3cret@idp.example.com/token\"",
                new ConnectException("Connection refused")));

    assertThat(FailureDescription.describe(failure))
        .isEqualTo(
            "OAuth2AuthorizationException: invalid_token_response <- ResourceAccessException"
                + " <- ConnectException");
  }

  /** A sibling of OAuth2AuthorizationException, not a subtype, so it needs its own extraction. */
  @Test
  void shouldNameTheErrorCodeOfAnOAuth2AuthenticationException() {
    final var failure =
        new OAuth2AuthenticationException(
            new OAuth2Error("invalid_request", "echoed request data", null),
            "message that must not be logged");

    assertThat(FailureDescription.describe(failure))
        .isEqualTo("OAuth2AuthenticationException: invalid_request");
  }

  /** AssertionJwkProvider's messages have been read and name only configuration, so they stay. */
  @Test
  void shouldKeepTheMessageOfAnExceptionThrownByTheAssertionJwkProvider() {
    final var failure = new IllegalStateException("No signing key for registration 'idp'");
    failure.setStackTrace(
        new StackTraceElement[] {
          new StackTraceElement(AssertionJwkProvider.class.getName(), "jwk", null, -1)
        });

    assertThat(FailureDescription.describe(failure))
        .isEqualTo("IllegalStateException: No signing key for registration 'idp'");
  }

  @Test
  void shouldStopAfterFourLinksOfTheChain() {
    final var failure =
        new RuntimeException(
            "1",
            new IllegalStateException(
                "2",
                new IllegalArgumentException(
                    "3", new UnsupportedOperationException("4", new ArithmeticException("5")))));

    assertThat(FailureDescription.describe(failure))
        .isEqualTo(
            "RuntimeException <- IllegalStateException <- IllegalArgumentException"
                + " <- UnsupportedOperationException");
  }
}
