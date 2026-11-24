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

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
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
            (request, real) -> {
              try {
                // The worker gets its connection only after the caller gave up.
                timedOut.await();
              } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException(e);
              }
              return real.send(request);
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
            (request, real) -> {
              entered.countDown();
              try {
                // Holds the worker where closing the connection cannot reach it.
                hold.await();
              } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException(e);
              }
              return real.send(request);
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
            (request, real) -> {
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
              return real.send(request);
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

  @Test
  void redirectIsNotFollowed() {
    endpoint.respondWith(302, "");
    endpoint.respondWithHeader("Location", endpoint.uri().toString());
    final var provider = provider();

    assertThat(catchThrowable(() -> authorization(provider)))
        .isInstanceOfSatisfying(
            TokenRequestException.class, e -> assertThat(e.getStatus()).isEqualTo(302));
    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void cancelBeforeExecuteNeverReachesTheEndpoint() throws Exception {
    final var request = new HttpUriRequestBase("POST", endpoint.uri());
    request.cancel();
    final List<Throwable> failures = new ArrayList<>();
    final var provider =
        provider(
            Duration.ofSeconds(5),
            (original, real) -> {
              try {
                return real.send(request);
              } catch (final IOException | RuntimeException e) {
                failures.add(e);
                throw e;
              }
            });

    assertThat(catchThrowable(() -> authorization(provider)))
        .isInstanceOf(TokenRequestException.class);
    assertThat(failures).hasSize(1);
    assertThat(endpoint.requestCount()).isZero();
  }

  /** A server that accepts the connection and never answers the TLS handshake. */
  @Test
  @Timeout(60)
  void cancelStopsAHungHandshake() throws Exception {
    try (var silent = new SilentServer()) {
      final var provider = silent.provider(Duration.ofSeconds(20), Duration.ofMillis(500));
      final long start = System.nanoTime();
      assertTimedOut(catchThrowable(() -> authorization(provider)));
      assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(5));

      // The 20 s read timeout is far away: only the cancel can have freed the worker. The next call
      // is not "still running", it starts a new handshake, and the cancel ends that one too.
      for (int i = 0; i < 2; i++) {
        final long again = System.nanoTime();
        assertTimedOut(catchThrowable(() -> authorization(provider)));
        assertThat(Duration.ofNanos(System.nanoTime() - again)).isLessThan(Duration.ofSeconds(5));
      }
      provider.close();
    }
  }

  @Test
  @Timeout(60)
  void handshakeTimeoutDoesNotBreakTheNextRequest() throws Exception {
    try (var silent = new SilentServer()) {
      final var provider = silent.provider(Duration.ofMillis(300), Duration.ofSeconds(20));
      for (int i = 0; i < 3; i++) {
        final Throwable failure = catchThrowable(() -> authorization(provider));
        assertThat(failure).isInstanceOf(TokenRequestException.class);
        assertThat(failure.getMessage()).doesNotContain("still running");
        assertThat(failure).hasCauseInstanceOf(IOException.class);
        assertThat(failure.getCause()).hasMessageNotContaining("closed");
      }
      provider.close();
    }
  }

  /** A loopback server that accepts connections and never answers. */
  private final class SilentServer implements AutoCloseable {
    private final ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
    private final List<Socket> accepted = new CopyOnWriteArrayList<>();

    SilentServer() throws IOException {
      final Thread acceptor =
          new Thread(
              () -> {
                try {
                  while (true) {
                    accepted.add(server.accept());
                  }
                } catch (final IOException e) {
                  // The test closed the server socket.
                }
              });
      acceptor.setDaemon(true);
      acceptor.start();
    }

    OidcClientCredentialsProvider provider(
        final Duration readTimeout, final Duration requestTimeout) {
      final var config =
          OidcClientCredentialsConfiguration.builder(
                  URI.create("https://localhost:" + server.getLocalPort() + "/token"),
                  "my-client",
                  SECRET)
              .connectTimeout(Duration.ofSeconds(20))
              .readTimeout(readTimeout)
              .requestTimeout(requestTimeout)
              .build();
      return new OidcClientCredentialsProvider(config, clock);
    }

    @Override
    public void close() throws IOException {
      server.close();
      for (final Socket socket : accepted) {
        socket.close();
      }
    }
  }
}
