/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;

/**
 * An outage of the provider gives a retryable 503, and a configuration error gives the server error
 * that no retry removes. The classification decides which of the two a failed resolution gets.
 */
class IdentityProviderOutageTest {

  @Test
  void shouldTreatAFailedIoExchangeAsAnOutage() {
    // given the failure Spring raises when discovery cannot connect, below the wrapper it adds
    final var failure =
        new IllegalArgumentException(
            "Unable to resolve Configuration",
            new ResourceAccessException(
                "timeout", new SocketTimeoutException("Connect timed out")));

    // when / then
    assertThat(IdentityProviderOutage.isCausing(failure)).isTrue();
  }

  @Test
  void shouldTreatAnIoFailureWithoutSpringWrapperAsAnOutage() {
    // given an I/O failure that a custom resolution wraps in an unchecked exception
    final var failure = new UncheckedIOException(new ConnectException("refused"));

    // when / then
    assertThat(IdentityProviderOutage.isCausing(failure)).isTrue();
  }

  @Test
  void shouldTreatAServerErrorAnswerOfTheProviderAsAnOutage() {
    // given a 5xx answer of the discovery endpoint
    final var failure =
        new IllegalArgumentException(
            "Unable to resolve Configuration",
            new HttpServerErrorException(HttpStatus.BAD_GATEWAY));

    // when / then
    assertThat(IdentityProviderOutage.isCausing(failure)).isTrue();
  }

  @Test
  void shouldNotTreatAClientErrorAnswerOfTheProviderAsAnOutage() {
    // given a 4xx answer of the discovery endpoint, which a wrong issuer-uri gives
    final var failure =
        new IllegalArgumentException(
            "Unable to resolve Configuration", new HttpClientErrorException(HttpStatus.NOT_FOUND));

    // when / then
    assertThat(IdentityProviderOutage.isCausing(failure)).isFalse();
  }

  @Test
  void shouldNotTreatAConfigurationFailureAsAnOutage() {
    // given a failure without an I/O or server error cause
    final var failure = new IllegalStateException("The issuer-uri is not valid");

    // when / then
    assertThat(IdentityProviderOutage.isCausing(failure)).isFalse();
  }

  @Test
  void shouldStopOnACauseChainThatPointsAtItself() {
    // given a failure that is its own cause
    final var failure =
        new RuntimeException("loop") {
          @Override
          public synchronized Throwable getCause() {
            return this;
          }
        };

    // when / then
    assertThat(IdentityProviderOutage.isCausing(failure)).isFalse();
  }
}
