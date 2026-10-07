/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class JWSKeySelectorFactoryTest {

  private static final String KID = "test-key-1";
  private static final Duration AWAIT_TIMEOUT = Duration.ofSeconds(5);

  @Test
  void shouldExposeTheDocumentedDefaultTimeoutsAndCacheBounds() {
    // Values are asserted explicitly (not just referenced via the production constants) so this
    // test fails if a future edit silently changes the documented bound in ADR-0032 — see that
    // ADR's "Decision" section for why each number was chosen.
    final var factory = new JWSKeySelectorFactory();

    assertThat(factory.getHttpConnectTimeoutMillis()).isEqualTo(3_000);
    assertThat(factory.getHttpReadTimeoutMillis()).isEqualTo(3_000);
    assertThat(factory.getCacheTimeToLiveMillis()).isEqualTo(300_000L);
    assertThat(factory.getCacheRefreshTimeoutMillis()).isEqualTo(15_000L);
    assertThat(factory.getRefreshAheadTimeMillis()).isEqualTo(30_000L);
  }

  @Test
  void shouldVerifyConcurrentlyWhileTheFirstJwksFetchIsStillInFlight() throws Exception {
    // given a JWKS endpoint that holds its response until the test releases it, so every caller
    // is guaranteed to hit the cache miss while the first fetch is still in flight. This exercises
    // Nimbus's existing single-flight fetch-on-cache-miss locking (already present via
    // `cache(true)` before this change). That the HTTP timeouts are long enough to ride out a slow
    // IdP is pinned by shouldExposeTheDocumentedDefaultTimeoutsAndCacheBounds, not by wall-clock
    // delays here.
    final var keyPair = generateRsaKeyPair();
    final var jwkSetJson = publicJwkSetJson(keyPair);
    final var requestCount = new AtomicInteger();
    final var gate = new CountDownLatch(1);
    try (var server = startGatedJwksServer(jwkSetJson, requestCount, gate)) {
      final var factory = new JWSKeySelectorFactory();
      final JWSKeySelector<?> selector = factory.createJWSKeySelector(server.jwksUri());
      final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();

      // when 20 threads call selectJWSKeys at the same time, forcing a concurrent cache miss
      final var threadCount = 20;
      final var executor = Executors.newFixedThreadPool(threadCount);
      final var startLatch = new CountDownLatch(1);
      try {
        final List<Callable<Integer>> tasks =
            IntStream.range(0, threadCount)
                .<Callable<Integer>>mapToObj(
                    i ->
                        () -> {
                          startLatch.await();
                          return selector.selectJWSKeys(header, null).size();
                        })
                .toList();
        final List<Future<Integer>> futures = tasks.stream().map(executor::submit).toList();
        startLatch.countDown();

        // and the endpoint has received the first fetch, which it is now holding open, while
        // every caller is still waiting on it
        await().atMost(AWAIT_TIMEOUT).until(() -> requestCount.get() >= 1);
        assertThat(futures).noneMatch(Future::isDone);
        gate.countDown();

        // then every thread gets the key — none fail with JWKSetUnavailableException
        for (final var future : futures) {
          assertThat(future.get(10, TimeUnit.SECONDS)).isEqualTo(1);
        }
        // and the JWKS endpoint is hit once, or at most a couple of times (one lock-holder plus,
        // rarely, one more thread that loses the lock race right as the first result lands) —
        // never once per thread.
        assertThat(requestCount.get()).isLessThanOrEqualTo(2);
      } finally {
        executor.shutdownNow();
      }
    }
  }

  @Test
  void shouldForceABoundedFetchOnExpiryRatherThanServingStaleKeysForever() throws Exception {
    // given a factory with a short, explicit staleness bound (500ms TTL / 100ms refresh-ahead /
    // 300ms refresh timeout)
    final var factory = shortTimingFactory();
    final var keyPair = generateRsaKeyPair();
    final var jwkSetJson = publicJwkSetJson(keyPair);
    final var requestCount = new AtomicInteger();
    try (var server = startJwksServer(jwkSetJson, requestCount)) {
      final JWSKeySelector<?> selector = factory.createJWSKeySelector(server.jwksUri());
      final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();

      // when the first call populates the cache
      assertThat(selector.selectJWSKeys(header, null)).hasSize(1);

      // and the IdP then goes down
      server.close();

      // then once the cache hard-expires (not just enters its refresh-ahead window), calls stop
      // silently serving the stale cached key — they force a fresh, bounded fetch that fails fast
      // because the source is down
      await()
          .atMost(AWAIT_TIMEOUT)
          .untilAsserted(
              () ->
                  assertThatThrownBy(() -> selector.selectJWSKeys(header, null))
                      .isInstanceOf(KeySourceException.class));
    }
  }

  @Test
  void shouldRefreshTheCachedJwkSetInTheBackgroundWithoutAnyFurtherRequests() throws Exception {
    // given a factory with short timings, so the scheduled refresh-ahead cadence
    // (ttl - refreshAhead - refreshTimeout = 100ms) fires several times inside the test
    final var factory = shortTimingFactory();
    final var keyPair = generateRsaKeyPair();
    final var jwkSetJson = publicJwkSetJson(keyPair);
    final var requestCount = new AtomicInteger();
    try (var server = startJwksServer(jwkSetJson, requestCount)) {
      final JWSKeySelector<?> selector = factory.createJWSKeySelector(server.jwksUri());
      final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();

      // when a single call populates the cache, which also starts the scheduled refresh
      assertThat(selector.selectJWSKeys(header, null)).hasSize(1);
      final var afterFirstCall = requestCount.get();

      // then, with nothing asking the selector for a key, the JWKS endpoint is still fetched
      // again, on the background schedule alone — this is the `scheduled = true` behaviour
      // ADR-0032 turns on, and the reason a provider serving near-zero traffic no longer lets its
      // cache lapse and block the next request that arrives
      await().atMost(AWAIT_TIMEOUT).until(() -> requestCount.get() > afterFirstCall);
    }
  }

  @Test
  void shouldKeepServingFromTheWarmCacheWhileTheBackgroundRefreshIsStuck() throws Exception {
    // given a primed cache and a JWKS endpoint that then hangs, so the scheduled refresh goes out
    // and never comes back while the cached keys are still valid
    final var factory = warmCacheWindowFactory();
    final var keyPair = generateRsaKeyPair();
    final var jwkSetJson = publicJwkSetJson(keyPair);
    final var requestCount = new AtomicInteger();
    final var gate = new AtomicReference<>(new CountDownLatch(0));
    try (var server = startGatedJwksServer(jwkSetJson, requestCount, gate)) {
      final JWSKeySelector<?> selector = factory.createJWSKeySelector(server.jwksUri());
      final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();
      assertThat(selector.selectJWSKeys(header, null)).hasSize(1);
      final var afterPriming = requestCount.get();
      final var stuck = new CountDownLatch(1);
      gate.set(stuck);

      // when the refresh reaches the endpoint, where it is held
      await().atMost(AWAIT_TIMEOUT).until(() -> requestCount.get() > afterPriming);

      // then 20 concurrent callers all still get the key, and they do so while the refresh is
      // still held — they read the warm cache rather than waiting on it (#612)
      final var threadCount = 20;
      final var executor = Executors.newFixedThreadPool(threadCount);
      try {
        final List<Callable<Integer>> tasks =
            IntStream.range(0, threadCount)
                .<Callable<Integer>>mapToObj(i -> () -> selector.selectJWSKeys(header, null).size())
                .toList();
        final var futures = executor.invokeAll(tasks, AWAIT_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
        assertThat(stuck.getCount()).isEqualTo(1);
        for (final var future : futures) {
          assertThat(future.isCancelled()).isFalse();
          assertThat(future.get()).isEqualTo(1);
        }
      } finally {
        stuck.countDown();
        executor.shutdownNow();
      }
    }
  }

  @Test
  void shouldWarnWithTheJwkSetUriWhenABackgroundRefreshFails() throws Exception {
    // given a cached JWK Set whose IdP then goes away, so the scheduled refresh has nothing to hit
    final var logger = (Logger) LoggerFactory.getLogger(JWSKeySelectorFactory.class);
    final var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    logger.addAppender(appender);
    final var factory = shortTimingFactory();
    final var keyPair = generateRsaKeyPair();
    final var jwkSetJson = publicJwkSetJson(keyPair);
    try (var server = startJwksServer(jwkSetJson, new AtomicInteger())) {
      final var jwksUri = server.jwksUri();
      final JWSKeySelector<?> selector = factory.createJWSKeySelector(jwksUri);
      final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();
      assertThat(selector.selectJWSKeys(header, null)).hasSize(1);

      // when the endpoint goes down and the background refresh runs
      server.close();

      // then the failure is logged at WARN with the JWK Set URI, rather than swallowed
      await()
          .atMost(AWAIT_TIMEOUT)
          .untilAsserted(
              () ->
                  assertThat(appender.list)
                      .anySatisfy(
                          event -> {
                            assertThat(event.getLevel()).isEqualTo(Level.WARN);
                            assertThat(event.getFormattedMessage()).contains(jwksUri);
                          }));
    } finally {
      logger.detachAppender(appender);
    }
  }

  @Test
  void shouldRunTheBackgroundRefreshSchedulerOnADaemonThreadSoAHostJvmCanStillExit()
      throws Exception {
    // given a factory with short timings, so the background refresh threads are created (lazily,
    // on first task submission) well inside the test's own runtime
    final var factory = shortTimingFactory();
    final var keyPair = generateRsaKeyPair();
    final var jwkSetJson = publicJwkSetJson(keyPair);
    try (var server = startJwksServer(jwkSetJson, new AtomicInteger())) {
      final JWSKeySelector<?> selector = factory.createJWSKeySelector(server.jwksUri());
      final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();

      // when a real fetch succeeds, which is what makes Nimbus schedule the background refresh
      assertThat(selector.selectJWSKeys(header, null)).hasSize(1);

      // then the scheduler thread behind that refresh is a daemon thread. Nimbus's own default
      // executors are non-daemon and nothing closes a JWKSource, so without this a host's JVM
      // would hang after its Spring context closed. Surefire cannot catch that — it exits its
      // fork explicitly — hence this direct assertion. The fetches themselves run on virtual
      // threads, which are always daemon. See ADR-0032.
      await()
          .atMost(AWAIT_TIMEOUT)
          .untilAsserted(
              () ->
                  assertThat(refreshSchedulerThreads())
                      .hasSize(1)
                      .allMatch(Thread::isDaemon, "is a daemon thread"));
    }
  }

  @Test
  void shouldForceAFreshFetchWhenKidIsUnknownEvenWithinTtl() throws Exception {
    // given a factory with a long TTL — deliberately NOT shortTimingFactory(), whose ~100ms
    // scheduled-refresh cadence would bump the request count between this test's two calls and
    // confuse an unrelated background refresh with the kid-miss fetch being asserted. Here the
    // cadence is ttl - refreshAhead - refreshTimeout = 58s, far outside the test's runtime, so the
    // only thing that can fetch is the test's own calls.
    final var factory = longTtlFactory();
    final var keyPair = generateRsaKeyPair();
    final var jwkSetJson = publicJwkSetJson(keyPair);
    final var requestCount = new AtomicInteger();
    try (var server = startJwksServer(jwkSetJson, requestCount)) {
      final JWSKeySelector<?> selector = factory.createJWSKeySelector(server.jwksUri());
      final var knownKidHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();

      // when the first call (for the known kid) populates the cache
      assertThat(selector.selectJWSKeys(knownKidHeader, null)).hasSize(1);
      assertThat(requestCount.get()).isEqualTo(1);

      // and a second call immediately follows, asking for a kid the cached set does not contain —
      // still well within the 60s TTL, so a TTL-expiry fetch is not what should explain this
      final var unknownKidHeader =
          new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("never-seen-kid").build();
      final var keysForUnknownKid = selector.selectJWSKeys(unknownKidHeader, null);

      // then the unrecognized kid forced a fresh, bounded fetch rather than silently answering
      // from the still-valid (but kid-incomplete) cache — the server was asked again, and since
      // its JWK Set still doesn't contain "never-seen-kid", no matching key is returned
      assertThat(requestCount.get()).isEqualTo(2);
      assertThat(keysForUnknownKid).isEmpty();
    }
  }

  private static List<Thread> refreshSchedulerThreads() {
    return Thread.getAllStackTraces().keySet().stream()
        .filter(
            thread -> thread.getName().equals(JWSKeySelectorFactory.REFRESH_SCHEDULER_THREAD_NAME))
        .toList();
  }

  private static JWSKeySelectorFactory shortTimingFactory() {
    // Same shape as the real defaults (refreshAheadTime + cacheRefreshTimeout <= timeToLive),
    // scaled from minutes down to hundreds of milliseconds so the tests run fast.
    return timingFactory(500L, 300L, 100L, 300);
  }

  /**
   * Same shape as the real defaults, but with the TTL left long enough that the scheduled
   * background refresh (cadence = {@code ttl - refreshAhead - cacheRefreshTimeout} = 58s) cannot
   * fire inside a test's runtime, while HTTP timeouts stay short so an unreachable server fails
   * fast.
   */
  private static JWSKeySelectorFactory longTtlFactory() {
    return timingFactory(60_000L, 1_000L, 1_000L, 300);
  }

  /**
   * Same shape as the real defaults, scaled to seconds: the scheduled refresh goes out a second
   * after the cache is loaded, and the cache hard-expires two seconds after that. That leaves a
   * window comfortably wider than any test body in which the cache is warm but a refresh is already
   * in flight.
   */
  private static JWSKeySelectorFactory warmCacheWindowFactory() {
    return timingFactory(3_000L, 1_000L, 1_000L, 2_000);
  }

  private static JWSKeySelectorFactory timingFactory(
      final long timeToLiveMillis,
      final long refreshTimeoutMillis,
      final long refreshAheadMillis,
      final int httpTimeoutMillis) {
    return new JWSKeySelectorFactory() {
      @Override
      protected long getCacheTimeToLiveMillis() {
        return timeToLiveMillis;
      }

      @Override
      protected long getCacheRefreshTimeoutMillis() {
        return refreshTimeoutMillis;
      }

      @Override
      protected long getRefreshAheadTimeMillis() {
        return refreshAheadMillis;
      }

      @Override
      protected int getHttpConnectTimeoutMillis() {
        return httpTimeoutMillis;
      }

      @Override
      protected int getHttpReadTimeoutMillis() {
        return httpTimeoutMillis;
      }
    };
  }

  private static KeyPair generateRsaKeyPair() throws Exception {
    final var generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    return generator.generateKeyPair();
  }

  private static String publicJwkSetJson(final KeyPair keyPair) {
    final var jwk =
        new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .keyID(KID)
            .build();
    return new JWKSet(jwk).toPublicJWKSet().toString();
  }

  /** Starts a loopback {@link HttpServer} serving {@code /jwks} immediately, counting requests. */
  private static JwksServer startJwksServer(
      final String jwkSetJson, final AtomicInteger requestCount) throws Exception {
    return startGatedJwksServer(jwkSetJson, requestCount, new CountDownLatch(0));
  }

  /**
   * Starts a loopback {@link HttpServer} serving {@code /jwks}, holding every response until {@code
   * gate} is released and counting how many requests it receives.
   */
  private static JwksServer startGatedJwksServer(
      final String jwkSetJson, final AtomicInteger requestCount, final CountDownLatch gate)
      throws Exception {
    return startGatedJwksServer(jwkSetJson, requestCount, new AtomicReference<>(gate));
  }

  /**
   * As above, but the gate can be swapped while the server runs, so a test can let early requests
   * through and then make the endpoint hang.
   */
  private static JwksServer startGatedJwksServer(
      final String jwkSetJson,
      final AtomicInteger requestCount,
      final AtomicReference<CountDownLatch> gate)
      throws Exception {
    final var httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    httpServer.createContext(
        "/jwks",
        exchange -> {
          try (exchange) {
            requestCount.incrementAndGet();
            if (!gate.get().await(10, TimeUnit.SECONDS)) {
              throw new IllegalStateException("The test never released the JWKS response");
            }
            final byte[] bytes = jwkSetJson.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
          } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
          }
        });
    httpServer.start();
    return new JwksServer(httpServer);
  }

  private record JwksServer(HttpServer server) implements AutoCloseable {
    String jwksUri() {
      return "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
    }

    @Override
    public void close() {
      server.stop(0);
    }
  }
}
