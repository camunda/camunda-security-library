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
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class JWSKeySelectorFactoryTest {

  private static final String KID = "test-key-1";

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
  void shouldVerifyConcurrentlyWhenJwksEndpointIsSlowButWithinConfiguredTimeout() throws Exception {
    // given a JWKS endpoint that takes 1.5s to respond — slower than Nimbus's own 500ms default
    // HTTP timeout, but within the 3s timeout this factory now configures (see ADR-0032). This
    // exercises Nimbus's existing single-flight fetch-on-cache-miss locking (already present via
    // `cache(true)` before this change) combined with the newly-raised HTTP timeout: the fetch
    // that was guaranteed to fail at 500ms now has enough headroom to succeed.
    final var keyPair = generateRsaKeyPair();
    final var jwkSetJson = publicJwkSetJson(keyPair);
    final var requestCount = new AtomicInteger();
    try (var server = startJwksServer(jwkSetJson, 1500L, requestCount)) {
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
    try (var server = startJwksServer(jwkSetJson, 0L, requestCount)) {
      final JWSKeySelector<?> selector = factory.createJWSKeySelector(server.jwksUri());
      final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();

      // when the first call populates the cache
      assertThat(selector.selectJWSKeys(header, null)).hasSize(1);

      // and the IdP then goes down, and enough time passes for the cache to hard-expire (not just
      // enter its refresh-ahead window)
      server.close();
      Thread.sleep(700L);

      // then the next call does not silently serve the (now 700ms-stale) cached key forever — it
      // forces a fresh, bounded fetch that fails fast because the source is down
      assertThatThrownBy(() -> selector.selectJWSKeys(header, null))
          .isInstanceOf(KeySourceException.class);
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
    try (var server = startJwksServer(jwkSetJson, 0L, requestCount)) {
      final JWSKeySelector<?> selector = factory.createJWSKeySelector(server.jwksUri());
      final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();

      // when a single call populates the cache, which also starts the scheduled refresh
      assertThat(selector.selectJWSKeys(header, null)).hasSize(1);
      final var afterFirstCall = requestCount.get();

      // and nothing asks the selector for a key for the next 500ms
      Thread.sleep(500L);

      // then the JWKS endpoint was still fetched again, on the background schedule alone — this is
      // the `scheduled = true` behaviour ADR-0032 turns on, and the reason a provider serving
      // near-zero traffic no longer lets its cache lapse and block the next request that arrives
      assertThat(requestCount.get()).isGreaterThan(afterFirstCall);
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
    try (var server = startJwksServer(jwkSetJson, 0L, new AtomicInteger())) {
      final JWSKeySelector<?> selector = factory.createJWSKeySelector(server.jwksUri());
      final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();

      // when a real fetch succeeds, which is what makes Nimbus schedule the background refresh
      assertThat(selector.selectJWSKeys(header, null)).hasSize(1);
      Thread.sleep(300L);

      // then the scheduler thread behind that refresh is a daemon thread. Nimbus's own default
      // executors are non-daemon and nothing closes a JWKSource, so without this a host's JVM
      // would hang after its Spring context closed. Surefire cannot catch that — it exits its
      // fork explicitly — hence this direct assertion. The fetches themselves run on virtual
      // threads, which are always daemon. See ADR-0032.
      final var schedulerThreads =
          Thread.getAllStackTraces().keySet().stream()
              .filter(
                  thread ->
                      thread.getName().equals(JWSKeySelectorFactory.REFRESH_SCHEDULER_THREAD_NAME))
              .toList();
      assertThat(schedulerThreads).hasSize(1);
      assertThat(schedulerThreads).allMatch(Thread::isDaemon, "is a daemon thread");
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
    try (var server = startJwksServer(jwkSetJson, 0L, requestCount)) {
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

  private static JWSKeySelectorFactory shortTimingFactory() {
    // Same shape as the real defaults (refreshAheadTime + cacheRefreshTimeout <= timeToLive),
    // scaled from minutes down to hundreds of milliseconds so the tests run fast.
    return new JWSKeySelectorFactory() {
      @Override
      protected long getCacheTimeToLiveMillis() {
        return 500L;
      }

      @Override
      protected long getCacheRefreshTimeoutMillis() {
        return 300L;
      }

      @Override
      protected long getRefreshAheadTimeMillis() {
        return 100L;
      }

      @Override
      protected int getHttpConnectTimeoutMillis() {
        return 300;
      }

      @Override
      protected int getHttpReadTimeoutMillis() {
        return 300;
      }
    };
  }

  /**
   * Same shape as the real defaults, but with the TTL left long enough that the scheduled
   * background refresh (cadence = {@code ttl - refreshAhead - cacheRefreshTimeout} = 58s) cannot
   * fire inside a test's runtime, while HTTP timeouts stay short so an unreachable server fails
   * fast.
   */
  private static JWSKeySelectorFactory longTtlFactory() {
    return new JWSKeySelectorFactory() {
      @Override
      protected long getCacheTimeToLiveMillis() {
        return 60_000L;
      }

      @Override
      protected long getCacheRefreshTimeoutMillis() {
        return 1_000L;
      }

      @Override
      protected long getRefreshAheadTimeMillis() {
        return 1_000L;
      }

      @Override
      protected int getHttpConnectTimeoutMillis() {
        return 300;
      }

      @Override
      protected int getHttpReadTimeoutMillis() {
        return 300;
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

  /**
   * Starts a loopback {@link HttpServer} serving {@code /jwks}, delaying every response by {@code
   * delayMillis} and counting how many requests it receives.
   */
  private static DelayedJwksServer startJwksServer(
      final String jwkSetJson, final long delayMillis, final AtomicInteger requestCount)
      throws Exception {
    final var httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    httpServer.createContext(
        "/jwks",
        exchange -> {
          try (exchange) {
            requestCount.incrementAndGet();
            try {
              Thread.sleep(delayMillis);
            } catch (final InterruptedException e) {
              Thread.currentThread().interrupt();
              throw new RuntimeException(e);
            }
            final byte[] bytes = jwkSetJson.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
          }
        });
    httpServer.start();
    return new DelayedJwksServer(httpServer);
  }

  private record DelayedJwksServer(HttpServer server) implements AutoCloseable {
    String jwksUri() {
      return "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
    }

    @Override
    public void close() {
      server.stop(0);
    }
  }
}
