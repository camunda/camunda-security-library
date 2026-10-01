/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
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
        // The factory/JWKSource built above is intentionally never closed: this is a single short
        // JVM-lifetime test process, so the one background refresh-ahead thread pair it starts
        // lives no longer than the test run. Production and long-lived test contexts are a
        // different concern, addressed in ADR-0032's accepted trade-offs.
        executor.shutdownNow();
      }
    }
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
