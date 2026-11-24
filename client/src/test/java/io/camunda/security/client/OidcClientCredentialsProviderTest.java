/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import io.camunda.security.client.OutboundCredentialsProvider.StatusCode;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class OidcClientCredentialsProviderTest extends OidcTestSupport {

  @Test
  void fetchesTokenAndSetsBearerHeader() throws IOException {
    assertThat(authorization(provider())).isEqualTo("Authorization=Bearer token-1");
  }

  @Test
  void secondCallUsesCachedToken() throws IOException {
    final var provider = provider();

    assertThat(authorization(provider)).isEqualTo(authorization(provider));
    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void refreshesBeforeTheTokenExpires() throws IOException {
    final var provider = provider();
    authorization(provider);

    clock.advance(Duration.ofSeconds(3600 - 31));
    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(1);

    clock.advance(Duration.ofSeconds(2));
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void unauthorizedFetchesANewTokenAndAsksForRetry() throws IOException {
    final var provider = provider();
    authorization(provider);

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isTrue();

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void unauthorizedWithTheSameTokenRecoversWhenTheIdpIssuesANewOne() throws IOException {
    final var provider = provider();
    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(1);
    endpoint.respondWith(
        200, "{\"access_token\":\"token-1\",\"token_type\":\"Bearer\",\"expires_in\":3600}");

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();
    assertThat(endpoint.requestCount()).isEqualTo(2);
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
    assertThat(endpoint.requestCount()).isEqualTo(2);

    endpoint.respondWith(
        200, "{\"access_token\":\"token-2\",\"token_type\":\"Bearer\",\"expires_in\":3600}");

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isTrue();
    assertThat(endpoint.requestCount()).isEqualTo(3);
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    assertThat(endpoint.requestCount()).isEqualTo(3);
  }

  @Test
  void unauthorizedMayBeReportedOnAnotherThreadThanTheOneThatApplied() throws Exception {
    final var provider = provider();
    final ExecutorService other = Executors.newSingleThreadExecutor();
    try {
      authorization(provider);

      final Future<Boolean> retry =
          other.submit(() -> provider.shouldRetryRequest(StatusCode.ofHttp(401)));

      assertThat(retry.get(10, TimeUnit.SECONDS)).isTrue();
      assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    } finally {
      other.shutdownNow();
    }
  }

  @Test
  void unauthorizedWithTheSameTokenAgainDoesNotAskForRetry() throws IOException {
    endpoint.respondWith(
        200, "{\"access_token\":\"fixed\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
    final var provider = provider();
    authorization(provider);

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void unauthorizedWhenTheIdpFailsDoesNotAskForRetryAndDoesNotThrow() throws IOException {
    final var provider = provider();
    authorization(provider);
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();
  }

  @Test
  void otherStatusesKeepTheTokenAndDoNotRetry() throws IOException {
    final var provider = provider();
    authorization(provider);

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(403))).isFalse();
    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(500))).isFalse();

    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void concurrentCallersShareOneTokenRequest() throws Exception {
    final var provider = provider();
    final int callers = 8;
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(callers);
    try {
      final List<Future<String>> results = new ArrayList<>();
      for (int i = 0; i < callers; i++) {
        results.add(pool.submit(() -> authorization(provider)));
      }
      pool.awaitAllWaiting();
      release.countDown();

      for (final Future<String> result : results) {
        assertThat(result.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-1");
      }
      assertThat(endpoint.requestCount()).isEqualTo(1);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void concurrentUnauthorizedReportsShareOneTokenRequest() throws Exception {
    final var provider = provider();
    authorization(provider);
    final int callers = 8;
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(callers);
    try {
      final List<Future<Boolean>> results = new ArrayList<>();
      for (int i = 0; i < callers; i++) {
        results.add(pool.submit(() -> provider.shouldRetryRequest(StatusCode.ofHttp(401))));
      }
      pool.awaitAllWaiting();
      release.countDown();

      for (final Future<Boolean> result : results) {
        assertThat(result.get(10, TimeUnit.SECONDS)).isTrue();
      }
      assertThat(endpoint.requestCount()).isEqualTo(2);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void unauthorizedWaitingForARefreshInFlightUsesItsResult() throws Exception {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3600));
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<String> refresh = pool.submit(() -> authorization(provider));
      awaitRequests(2);
      final Future<Boolean> retry =
          pool.submit(() -> provider.shouldRetryRequest(StatusCode.ofHttp(401)));
      pool.awaitAllWaiting();
      release.countDown();

      assertThat(refresh.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-2");
      assertThat(retry.get(10, TimeUnit.SECONDS)).isTrue();
      assertThat(endpoint.requestCount()).isEqualTo(2);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void connectionRefusedFailsWithoutAResponseStatus() throws IOException {
    final URI closed;
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      closed = URI.create("http://127.0.0.1:" + socket.getLocalPort() + "/token");
    }
    final var provider = provider(closed, clock);

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE);
              assertThat(e.getError()).isNull();
              assertThat(e.getMessage()).contains("my-client").doesNotContain(SECRET);
              assertThat(e).hasCauseInstanceOf(IOException.class);
            });
  }

  @Test
  void transportFailureHidesTheQueryOfTheTokenUriInTheWholeCauseChain() throws IOException {
    final URI closed;
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      closed = URI.create("http://127.0.0.1:" + socket.getLocalPort() + "/token?key=qs-secret");
    }
    final var provider = provider(closed, clock);

    final Throwable failure = catchThrowable(() -> authorization(provider));

    assertThat(failure).isInstanceOf(TokenRequestException.class);
    for (Throwable t = failure; t != null; t = t.getCause()) {
      assertThat(String.valueOf(t.getMessage())).doesNotContain("qs-secret");
    }
    assertThat(failure.getMessage()).contains("127.0.0.1:" + closed.getPort() + "/token");
  }

  @Test
  void expiryCountsFromTheTimeTheRequestWasSent() throws Exception {
    final var provider = provider();
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(1);
    try {
      final Future<String> first = pool.submit(() -> authorization(provider));
      awaitRequests(1);
      clock.advance(Duration.ofSeconds(3600));
      release.countDown();
      assertThat(first.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-1");
    } finally {
      release.countDown();
      pool.shutdownNow();
    }

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void unauthorizedWhenTheRefreshFailsDropsTheRejectedToken() throws IOException {
    final var provider = provider();
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();

    endpoint.respondWith(
        200, "{\"access_token\":\"fresh\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer fresh");
    assertThat(endpoint.requestCount()).isEqualTo(3);
  }

  @Test
  void failedRefreshKeepsSendingTheOldTokenUntilItExpires() throws IOException {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
    assertThat(endpoint.requestCount()).isEqualTo(2);

    clock.advance(Duration.ofSeconds(11));
    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class, e -> assertThat(e.getStatus()).isEqualTo(503));
  }

  @Test
  void failedRefreshAfterUnauthorizedDoesNotSendTheRejectedToken() throws IOException {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();

    assertThatThrownBy(() -> authorization(provider)).isInstanceOf(TokenRequestException.class);
  }

  @Test
  void callersDuringARefreshAfterUnauthorizedWaitForTheNewToken() throws Exception {
    final var provider = provider();
    authorization(provider);
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<Boolean> retry =
          pool.submit(() -> provider.shouldRetryRequest(StatusCode.ofHttp(401)));
      awaitRequests(2);
      final Future<String> caller = pool.submit(() -> authorization(provider));
      pool.awaitAllWaiting();
      release.countDown();

      assertThat(retry.get(10, TimeUnit.SECONDS)).isTrue();
      assertThat(caller.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-2");
    } finally {
      release.countDown();
      pool.shutdownNow();
    }

    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void failedRefreshThatKeepsTheOldTokenWarnsOnceInARow() throws IOException {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");

    try (var logs = new LogCapture()) {
      assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
      assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
      assertThat(endpoint.requestCount()).isEqualTo(3);

      endpoint.respondWith(
          200, "{\"access_token\":\"token-9\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
      clock.advance(Duration.ofSeconds(5));
      assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-9");

      clock.advance(Duration.ofSeconds(3590));
      endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");
      assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-9");

      final List<ILoggingEvent> failures = logs.eventsContaining("Token refresh for client");
      assertThat(failures)
          .extracting(ILoggingEvent::getLevel)
          .containsExactly(Level.WARN, Level.DEBUG, Level.WARN);
      assertThat(failures)
          .allSatisfy(
              event ->
                  assertThat(event.getFormattedMessage())
                      .contains("my-client", "HTTP 503")
                      .doesNotContain(SECRET, "token-1", "token-9"));
    }
  }

  @Test
  void refreshStartsExactlyAtRefreshAt() throws IOException {
    final var provider = provider();
    final Instant sentAt = clock.instant();
    authorization(provider);
    final Instant refreshAt = sentAt.plusSeconds(3600).minusSeconds(Math.min(30, 3600 / 2));

    clock.advance(Duration.between(clock.instant(), refreshAt).minusNanos(1));
    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(1);

    clock.advance(Duration.ofNanos(1));
    assertThat(clock.instant()).isEqualTo(refreshAt);
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void unexpectedRuntimeExceptionFailsAsTokenRequestExceptionAndTheNextCallFetchesAgain()
      throws IOException {
    final ThrowingClock throwingClock = new ThrowingClock();
    final var provider = provider(endpoint.uri(), throwingClock);
    throwingClock.arm();

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE);
              assertThat(e).hasCauseInstanceOf(IllegalStateException.class);
            });

    throwingClock.disarm();
    // The clock fails before the request is sent, so the endpoint issues its first token only now.
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void callAfterCloseFails() {
    final var provider = provider();

    provider.close();

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE));
    assertThat(endpoint.requestCount()).isZero();
  }

  @Test
  void callAfterCloseFailsWithACachedToken() throws IOException {
    final var provider = provider();
    authorization(provider);

    provider.close();

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE);
              assertThat(e.getMessage()).contains("closed");
            });
    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void callAfterCloseDoesNotKeepTheOldToken() throws IOException {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));

    provider.close();

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE));
    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void closeDuringARefreshDoesNotKeepTheOldToken() throws Exception {
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch hold = new CountDownLatch(1);
    final AtomicBoolean first = new AtomicBoolean(true);
    final var provider =
        provider(
            Duration.ofSeconds(10),
            (request, connection) -> {
              if (first.getAndSet(false)) {
                return TokenRequestWorker.sendOverConnection(request, connection);
              }
              entered.countDown();
              try {
                hold.await();
              } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException(e);
              }
              return TokenRequestWorker.sendOverConnection(request, connection);
            });
    final ExecutorService other = Executors.newSingleThreadExecutor();
    try {
      authorization(provider);
      clock.advance(Duration.ofSeconds(3590));
      final Future<String> refresh = other.submit(() -> authorization(provider));
      assertThat(entered.await(10, TimeUnit.SECONDS)).isTrue();

      provider.close();

      final Throwable failure = catchThrowable(() -> refresh.get(10, TimeUnit.SECONDS));
      assertThat(failure)
          .isInstanceOf(ExecutionException.class)
          .cause()
          .isInstanceOfSatisfying(
              TokenRequestException.class,
              e -> {
                assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE);
                assertThat(e.getMessage()).contains("the provider is closed");
              });
    } finally {
      hold.countDown();
      other.shutdownNow();
    }
  }

  @Test
  void unauthorizedAfterCloseDoesNotAskForRetry() {
    final var provider = provider();

    provider.close();

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();
  }

  @Test
  void interruptedWaiterFailsWithIoExceptionAndKeepsTheInterruptFlag() throws Exception {
    final var provider = provider();
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<String> fetcher = pool.submit(() -> authorization(provider));
      pool.awaitAllWaiting();
      final AtomicBoolean flagKept = new AtomicBoolean();
      final Future<String> waiter =
          pool.submit(
              () -> {
                try {
                  return authorization(provider);
                } finally {
                  flagKept.set(Thread.currentThread().isInterrupted());
                }
              });
      pool.awaitAllWaiting();
      pool.threads().getLast().interrupt();

      assertThatThrownBy(() -> waiter.get(10, TimeUnit.SECONDS))
          .hasCauseInstanceOf(IOException.class)
          .hasMessageContaining("Interrupted")
          .hasMessageContaining("my-client");
      assertThat(flagKept).isTrue();

      release.countDown();
      assertThat(fetcher.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-1");
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void interruptedWaiterFailsEvenWhileTheOldTokenIsValid() throws Exception {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<String> fetcher = pool.submit(() -> authorization(provider));
      pool.awaitAllWaiting();
      final AtomicBoolean flagKept = new AtomicBoolean();
      final Future<String> waiter =
          pool.submit(
              () -> {
                try {
                  return authorization(provider);
                } finally {
                  flagKept.set(Thread.currentThread().isInterrupted());
                }
              });
      pool.awaitAllWaiting();
      pool.threads().getLast().interrupt();

      assertThatThrownBy(() -> waiter.get(10, TimeUnit.SECONDS))
          .hasCauseInstanceOf(IOException.class)
          .hasMessageContaining("Interrupted")
          .hasMessageContaining("my-client");
      assertThat(flagKept).isTrue();

      release.countDown();
      assertThat(fetcher.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-2");
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  /** A clock that fails once armed; the provider reads it before it sends a token request. */
  private static final class ThrowingClock extends Clock {
    private volatile boolean armed;

    void arm() {
      armed = true;
    }

    void disarm() {
      armed = false;
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(final ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      if (armed) {
        throw new IllegalStateException("clock failure");
      }
      return Instant.parse("2026-01-01T00:00:00Z");
    }
  }
}
