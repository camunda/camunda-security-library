/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.LoggerFactory;

abstract class OidcTestSupport {

  static final String SECRET = "s3cr3t-value";
  TokenEndpoint endpoint;
  MutableClock clock;

  /**
   * Loads the Nimbus classes once, so that the first token request of a test does not spend its
   * short request timeout on class loading.
   */
  @BeforeAll
  static void loadTokenRequestClasses() {
    TokenResponses.buildRequest(
        OidcClientCredentialsConfiguration.builder(
                URI.create("https://localhost/token"), "warm-up", SECRET)
            .build());
  }

  @BeforeEach
  void setUp() throws IOException {
    endpoint = new TokenEndpoint();
    clock = new MutableClock();
  }

  @AfterEach
  void tearDown() {
    endpoint.close();
  }

  OidcClientCredentialsProvider provider(
      final String audience, final List<String> scopes, final String resource) {
    final var config =
        OidcClientCredentialsConfiguration.builder(endpoint.uri(), "my-client", SECRET)
            .audience(audience)
            .scopes(scopes)
            .resource(resource)
            .build();
    return new OidcClientCredentialsProvider(config, clock);
  }

  OidcClientCredentialsProvider provider(final URI tokenUri, final Clock tokenClock) {
    final var config =
        OidcClientCredentialsConfiguration.builder(tokenUri, "my-client", SECRET).build();
    return new OidcClientCredentialsProvider(config, tokenClock);
  }

  OidcClientCredentialsProvider provider(
      final Duration connectTimeout, final Duration readTimeout) {
    final var config =
        OidcClientCredentialsConfiguration.builder(endpoint.uri(), "my-client", SECRET)
            .connectTimeout(connectTimeout)
            .readTimeout(readTimeout)
            .build();
    return new OidcClientCredentialsProvider(config, clock);
  }

  OidcClientCredentialsProvider provider(
      final Duration requestTimeout, final TokenRequestWorker.TokenSender sender) {
    // A long read timeout, so that only the request timeout can end a request.
    final var config =
        OidcClientCredentialsConfiguration.builder(endpoint.uri(), "my-client", SECRET)
            .readTimeout(Duration.ofSeconds(60))
            .requestTimeout(requestTimeout)
            .build();
    return new OidcClientCredentialsProvider(config, clock, sender);
  }

  OidcClientCredentialsProvider providerWithRequestTimeout(final Duration requestTimeout) {
    return provider(requestTimeout, TokenRequestWorker::sendOverConnection);
  }

  /** Calls until the worker is free again; fails if it is still busy after 10 seconds. */
  static String authorizationOnceTheWorkerIsFree(final OutboundCredentialsProvider provider)
      throws Exception {
    final AtomicReference<String> result = new AtomicReference<>();
    await("the worker was not freed")
        .atMost(Duration.ofSeconds(10))
        .pollInterval(Duration.ofMillis(5))
        .pollInSameThread()
        .until(
            () -> {
              try {
                result.set(authorization(provider));
                return true;
              } catch (final TokenRequestException e) {
                assertThat(e.getMessage()).contains("still running");
                return false;
              }
            });
    return result.get();
  }

  static void assertTimedOut(final Throwable failure) {
    assertThat(failure)
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE);
              assertThat(e.getMessage()).contains("my-client", "did not finish within");
            });
  }

  /** No message in the cause chain may contain any of the given texts. */
  static void assertNoneOfTheMessagesContains(final Throwable failure, final String... texts) {
    for (Throwable t = failure; t != null; t = t.getCause()) {
      assertThat(String.valueOf(t.getMessage())).doesNotContain(texts);
    }
  }

  /** Waits until the endpoint has received the given number of token requests. */
  void awaitRequests(final int expected) {
    await("token request did not arrive")
        .atMost(Duration.ofSeconds(10))
        .pollInterval(Duration.ofMillis(5))
        .until(() -> endpoint.requestCount() >= expected);
  }

  static TokenRequestException failureOf(final Future<?> result) throws Exception {
    try {
      result.get(10, TimeUnit.SECONDS);
    } catch (final ExecutionException e) {
      assertThat(e.getCause()).isInstanceOf(TokenRequestException.class);
      return (TokenRequestException) e.getCause();
    }
    throw new AssertionError("expected the call to fail");
  }

  OidcClientCredentialsProvider provider() {
    return provider(null, null, null);
  }

  static String authorization(final OutboundCredentialsProvider provider) throws IOException {
    final List<String> values = new ArrayList<>();
    provider.applyCredentials((header, value) -> values.add(header + "=" + value));
    return values.getFirst();
  }

  /** Captures the logs of the client package at DEBUG; restores the logger when closed. */
  static final class LogCapture implements AutoCloseable {
    private final Logger logger = (Logger) LoggerFactory.getLogger("io.camunda.security.client");
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private final Level oldLevel = logger.getLevel();
    private final boolean oldAdditive = logger.isAdditive();

    LogCapture() {
      appender.start();
      logger.addAppender(appender);
      logger.setLevel(Level.DEBUG);
      logger.setAdditive(false);
    }

    List<ILoggingEvent> eventsContaining(final String text) {
      return appender.list.stream()
          .filter(event -> event.getFormattedMessage().contains(text))
          .toList();
    }

    @Override
    public void close() {
      logger.detachAppender(appender);
      logger.setLevel(oldLevel);
      logger.setAdditive(oldAdditive);
      appender.stop();
    }
  }

  /** Pool with one thread per caller, so a test can tell when every caller is parked. */
  static final class Callers {
    private final List<Thread> threads = new CopyOnWriteArrayList<>();
    private final ExecutorService executor;

    Callers(final int size) {
      executor =
          Executors.newFixedThreadPool(
              size,
              runnable -> {
                final Thread thread = new Thread(runnable);
                threads.add(thread);
                return thread;
              });
    }

    <T> Future<T> submit(final Callable<T> task) {
      return executor.submit(task);
    }

    List<Thread> threads() {
      return threads;
    }

    /**
     * Waits until every started caller is parked: one blocked on the token request, the others on
     * the lock.
     */
    void awaitAllWaiting() {
      await("callers did not park in time")
          .atMost(Duration.ofSeconds(10))
          .pollInterval(Duration.ofMillis(5))
          .until(this::allParked);
    }

    private boolean allParked() {
      return threads.stream().allMatch(Callers::isParked);
    }

    /** Waiting on the lock, or inside the token request: the caller that sent the request. */
    private static boolean isParked(final Thread thread) {
      if (thread.getState() == Thread.State.WAITING
          || thread.getState() == Thread.State.TIMED_WAITING) {
        return true;
      }
      return thread.getState() == Thread.State.RUNNABLE
          && Arrays.stream(thread.getStackTrace())
              .anyMatch(frame -> frame.getClassName().equals(HTTPRequest.class.getName()));
    }

    void shutdownNow() {
      executor.shutdownNow();
    }
  }
}
