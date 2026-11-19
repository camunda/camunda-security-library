/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.verifyNoInteractions;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.spring.oidc.DeferredJwtDecoder;
import io.camunda.security.spring.oidc.IdentityProviderUnavailableException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Covers how the failure handler answers a decoder that reports an unavailable identity provider,
 * and what it writes to the log for it.
 */
@ExtendWith(MockitoExtension.class)
class LoggingAuthenticationFailureHandlerTest {

  @Mock private AuthenticationFailureHandler delegate;
  @InjectMocks private LoggingAuthenticationFailureHandler handler;
  private Logger handlerLogger;
  private Level originalLevel;
  private ListAppender<ILoggingEvent> logs;

  @BeforeEach
  void attachAppender() {
    handlerLogger = (Logger) LoggerFactory.getLogger(LoggingAuthenticationFailureHandler.class);
    originalLevel = handlerLogger.getLevel();
    handlerLogger.setLevel(Level.DEBUG);
    logs = new ListAppender<>();
    logs.start();
    handlerLogger.addAppender(logs);
  }

  @AfterEach
  void detachAppender() {
    handlerLogger.detachAppender(logs);
    handlerLogger.setLevel(originalLevel);
  }

  @Test
  void shouldAnswer503AndKeepTheTextOfTheFailureOutOfTheLog() throws Exception {
    // given a decoder that fails with a message that quotes an endpoint with credentials, wrapped
    // by Spring Security into an AuthenticationServiceException as the bearer filter hands it over
    final var decoder =
        new DeferredJwtDecoder(
            () -> {
              throw new IllegalStateException("GET https://user:s3cret@idp.example.com/discovery");
            });
    final var unavailable = catchThrowable(() -> decoder.decode("token"));
    assertThat(unavailable).isInstanceOf(IdentityProviderUnavailableException.class);
    final var failure = new AuthenticationServiceException(unavailable.getMessage(), unavailable);
    final var response = new MockHttpServletResponse();

    // when the handler answers the failure
    handler.onAuthenticationFailure(new MockHttpServletRequest(), response, failure);

    // then the status is 503, and no log line of the handler holds the text of the failure
    assertThat(response.getStatus()).isEqualTo(503);
    assertThat(logs.list).isNotEmpty();
    assertThat(logs.list)
        .allSatisfy(
            event -> {
              assertThat(event.getFormattedMessage()).doesNotContain("s3cret");
              assertThat(event.getThrowableProxy()).isNull();
            });
  }

  @Test
  void shouldKeepAnswering500ForOtherTechnicalFailures() throws Exception {
    // given a technical failure that is not an unavailable identity provider
    final var failure =
        new AuthenticationServiceException("broken", new IllegalStateException("broken"));
    final var response = new MockHttpServletResponse();

    // when the handler answers the failure
    handler.onAuthenticationFailure(new MockHttpServletRequest(), response, failure);

    // then the answer stays a server error, and the failure is logged at WARN
    assertThat(response.getStatus()).isEqualTo(500);
    assertThat(logs.list).anyMatch(event -> event.getLevel() == Level.WARN);
    verifyNoInteractions(delegate);
  }
}
