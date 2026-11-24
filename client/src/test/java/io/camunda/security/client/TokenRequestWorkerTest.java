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

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class TokenRequestWorkerTest extends OidcTestSupport {

  @Test
  @Timeout(30)
  void requestAfterATimedOutOneSucceeds() throws Exception {
    final var provider = providerWithRequestTimeout(Duration.ofMillis(300));
    final CountDownLatch release = endpoint.blockFirstResponse();
    try {
      final long start = System.nanoTime();
      assertTimedOut(catchThrowable(() -> authorization(provider)));
      assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(5));

      // The first exchange is still held: only closing the connection frees the worker.
      assertThat(authorizationOnceTheWorkerIsFree(provider))
          .isEqualTo("Authorization=Bearer token-1");
      assertThat(release.getCount()).isEqualTo(1);
    } finally {
      release.countDown();
    }
  }

  @Test
  @Timeout(30)
  void timeoutBeforeTheConnectionIsOpenStillFreesTheWorker() throws Exception {
    final CountDownLatch timedOut = new CountDownLatch(1);
    final var provider =
        provider(
            Duration.ofMillis(200),
            (request, connection) -> {
              try {
                // The worker gets its connection only after the caller gave up.
                timedOut.await();
              } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException(e);
              }
              return TokenRequestWorker.sendOverConnection(request, connection);
            });
    final CountDownLatch release = endpoint.blockResponses();
    try {
      assertTimedOut(catchThrowable(() -> authorization(provider)));
      timedOut.countDown();

      // The worker closes the connection that it opened too late, before the request is sent.
      // Without that, it would wait for the held response, and every call would fail fast.
      final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
      Throwable next = catchThrowable(() -> authorization(provider));
      while (next.getMessage().contains("still running")) {
        assertThat(System.nanoTime()).as("the worker was not freed").isLessThan(deadline);
        TimeUnit.MILLISECONDS.sleep(5);
        next = catchThrowable(() -> authorization(provider));
      }
      assertTimedOut(next);
      assertThat(endpoint.requestCount()).isEqualTo(1);
    } finally {
      release.countDown();
    }
  }

  @Test
  @Timeout(30)
  void slowResponseEndsAtTheRequestTimeout() throws Exception {
    final var provider = providerWithRequestTimeout(Duration.ofMillis(300));
    endpoint.respondSlowly(Duration.ofMillis(50));

    final long start = System.nanoTime();
    assertTimedOut(catchThrowable(() -> authorization(provider)));

    assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));
    endpoint.respondSlowly(Duration.ZERO);
    assertThat(authorizationOnceTheWorkerIsFree(provider)).startsWith("Authorization=Bearer ");
  }

  @Test
  @Timeout(30)
  void callWhileAHungRequestIsStillRunningFailsFast() throws Exception {
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch hold = new CountDownLatch(1);
    final var provider =
        provider(
            Duration.ofMillis(200),
            (request, connection) -> {
              entered.countDown();
              try {
                // Holds the worker where closing the connection cannot reach it.
                hold.await();
              } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException(e);
              }
              return TokenRequestWorker.sendOverConnection(request, connection);
            });
    try {
      assertTimedOut(catchThrowable(() -> authorization(provider)));
      // On a slow machine a call can time out before the worker starts it. Call until it is held.
      while (entered.getCount() > 0) {
        assertThat(catchThrowable(() -> authorization(provider)))
            .isInstanceOfSatisfying(
                TokenRequestException.class,
                e -> assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE));
      }

      assertThatThrownBy(() -> authorization(provider))
          .isInstanceOfSatisfying(
              TokenRequestException.class,
              e -> {
                assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE);
                assertThat(e.getMessage()).contains("my-client", "still running");
              });
      assertThat(endpoint.requestCount()).isZero();
    } finally {
      hold.countDown();
    }
    assertThat(authorizationOnceTheWorkerIsFree(provider)).startsWith("Authorization=Bearer ");
  }

  @Test
  @Timeout(30)
  void refreshThatRunsOutOfTimeKeepsAValidOldToken() throws Exception {
    final var provider = providerWithRequestTimeout(Duration.ofSeconds(1));
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
    clock.advance(Duration.ofSeconds(3590));
    final CountDownLatch release = endpoint.blockResponses();
    try {
      final long start = System.nanoTime();
      assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
      assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(5));

      // After the expiry, the old token is not used any more.
      clock.advance(Duration.ofSeconds(20));
      assertThat(catchThrowable(() -> authorization(provider)))
          .isInstanceOfSatisfying(
              TokenRequestException.class,
              e -> assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE));
    } finally {
      release.countDown();
    }
  }

  @Test
  @Timeout(30)
  void callWhileAHungRefreshStillRunsKeepsAValidOldToken() throws Exception {
    final AtomicBoolean holdNext = new AtomicBoolean();
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch hold = new CountDownLatch(1);
    final var provider =
        provider(
            Duration.ofSeconds(1),
            (request, connection) -> {
              if (holdNext.get()) {
                entered.countDown();
                try {
                  // Holds the worker where closing the connection cannot reach it.
                  hold.await();
                } catch (final InterruptedException e) {
                  Thread.currentThread().interrupt();
                  throw new IOException(e);
                }
              }
              return TokenRequestWorker.sendOverConnection(request, connection);
            });
    try {
      assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
      clock.advance(Duration.ofSeconds(3590));
      holdNext.set(true);
      // On a slow machine a call can time out before the worker starts it. Call until it is held.
      do {
        assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
      } while (entered.getCount() > 0);

      try (var logs = new LogCapture()) {
        assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
        assertThat(logs.eventsContaining("still running")).isNotEmpty();
      }
    } finally {
      hold.countDown();
    }
  }

  @Test
  @Timeout(30)
  void closeFailsAQueuedRequestAtOnce() throws Exception {
    final CountDownLatch queued = new CountDownLatch(1);
    final ThreadPoolExecutor executor =
        new ThreadPoolExecutor(
            1,
            1,
            60,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<Runnable>() {
              @Override
              public boolean offer(final Runnable task) {
                final boolean added = super.offer(task);
                queued.countDown();
                return added;
              }
            });
    final var config =
        OidcClientCredentialsConfiguration.builder(endpoint.uri(), "my-client", SECRET).build();
    final var worker =
        new TokenRequestWorker(config, TokenRequestWorker::sendOverConnection, executor);
    final CountDownLatch started = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    // Holds the one worker thread, so that the next request waits in the queue.
    executor.execute(
        () -> {
          started.countDown();
          try {
            release.await();
          } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
          }
        });
    final Callers pool = new Callers(1);
    try {
      started.await();
      final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
      final Future<HTTPResponse> call =
          pool.submit(() -> worker.send(TokenResponses.buildRequest(config), deadline));
      queued.await();

      final long start = System.nanoTime();
      worker.close();

      final TokenRequestException failure = failureOf(call);
      assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(5));
      assertThat(failure.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE);
      assertThat(failure.getMessage()).contains("the provider is closed");
      assertThat(endpoint.requestCount()).isZero();
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void responseLargerThanTheLimitFails() {
    endpoint.respondWith(200, "x".repeat(TokenRequestWorker.MAX_RESPONSE_BYTES + 1));

    assertTooLarge(catchThrowable(() -> authorization(provider())), 200);
  }

  @Test
  void errorResponseLargerThanTheLimitFails() {
    endpoint.respondWith(500, "x".repeat(TokenRequestWorker.MAX_RESPONSE_BYTES + 1));

    assertTooLarge(catchThrowable(() -> authorization(provider())), 500);
  }

  @Test
  void responseAtTheLimitIsRead() throws IOException {
    final String start = "{\"access_token\":\"big-token\",\"token_type\":\"bearer\",\"pad\":\"";
    final String end = "\"}";
    final String pad =
        "x".repeat(TokenRequestWorker.MAX_RESPONSE_BYTES - start.length() - end.length());
    endpoint.respondWith(200, start + pad + end);

    assertThat(authorization(provider())).isEqualTo("Authorization=Bearer big-token");
  }

  private static void assertTooLarge(final Throwable failure, final int status) {
    assertThat(failure)
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(status);
              assertThat(e.getMessage())
                  .contains("my-client", "larger than 64 KiB")
                  .doesNotContain("xxxx");
            });
  }

  @Test
  @Timeout(30)
  void waiterFailsWithinTheRequestTimeoutInTotal() throws Exception {
    final var provider = providerWithRequestTimeout(Duration.ofMillis(500));
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(1);
    try {
      final Future<String> first = pool.submit(() -> authorization(provider));
      awaitRequests(1);

      final long start = System.nanoTime();
      final Throwable failure = catchThrowable(() -> authorization(provider));

      assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(1500));
      assertThat(failure)
          .isInstanceOfSatisfying(
              TokenRequestException.class,
              e -> assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE));
      assertTimedOut(failureOf(first));
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void interruptDuringTheTokenRequestFailsEvenWithAValidOldToken() throws Exception {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(1);
    try {
      final AtomicBoolean flagKept = new AtomicBoolean();
      final Future<String> caller =
          pool.submit(
              () -> {
                try {
                  return authorization(provider);
                } finally {
                  flagKept.set(Thread.currentThread().isInterrupted());
                }
              });
      awaitRequests(2);
      pool.awaitAllWaiting();
      pool.threads().getLast().interrupt();

      assertThat(failureOf(caller).getMessage()).contains("my-client", "interrupted");
      assertThat(flagKept).isTrue();
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void readTimeoutEndsABlockedTokenRequest() throws Exception {
    final var provider = provider(null, Duration.ofMillis(200));
    final CountDownLatch release = endpoint.blockResponses();
    try {
      final Throwable failure = catchThrowable(() -> authorization(provider));

      assertThat(failure).isInstanceOf(TokenRequestException.class);
      assertThat(((TokenRequestException) failure).getStatus())
          .isEqualTo(TokenRequestException.NO_RESPONSE);
      assertThat(failure).hasMessageContaining("my-client").hasCauseInstanceOf(IOException.class);
      assertThat(endpoint.requestCount()).isEqualTo(1);
    } finally {
      release.countDown();
    }
  }

  @Test
  void aTimeoutBelowOneMillisecondStillTimesOut() {
    final var provider = provider(null, Duration.ofNanos(500_000));
    final CountDownLatch release = endpoint.blockResponses();
    try {
      assertThatThrownBy(() -> authorization(provider))
          .isInstanceOf(TokenRequestException.class)
          .hasCauseInstanceOf(IOException.class);
    } finally {
      release.countDown();
    }
  }
}
