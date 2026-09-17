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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderInitializationException;

class DeferredJwtDecoderTest {

  private static final Jwt TOKEN =
      Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();

  @Test
  void shouldRejectAMissingDelegateSupplier() {
    // then the wiring error names the argument, and not a later decode
    assertThatThrownBy(() -> new DeferredJwtDecoder(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("delegateSupplier must not be null");
  }

  @Test
  void shouldKeepTheDelegateAfterASuccessfulBuild() {
    // given
    final var builds = new AtomicInteger();
    final var decoder = new DeferredJwtDecoder(() -> decoderThatCounts(builds));

    // when
    decoder.decode("token");
    decoder.decode("token");

    // then the delegate is built at the first decode only, so discovery runs once
    assertThat(builds).hasValue(1);
  }

  @Test
  void shouldBuildTheDelegateAgainAfterAFailedBuild() {
    // given a provider that is unreachable for the first build
    final var builds = new AtomicInteger();
    final var decoder =
        new DeferredJwtDecoder(
            () -> {
              if (builds.incrementAndGet() == 1) {
                throw new IllegalStateException("unreachable");
              }
              return unused -> TOKEN;
            });
    assertThatThrownBy(() -> decoder.decode("token"))
        .isInstanceOf(JwtDecoderInitializationException.class)
        .hasRootCauseInstanceOf(IllegalStateException.class);

    // when the provider answers again
    final var jwt = decoder.decode("token");

    // then the deployment recovers without a restart
    assertThat(jwt).isEqualTo(TOKEN);
    assertThat(builds).hasValue(2);
  }

  @Test
  void shouldLetConcurrentDecodesBuildAtTheSameTime() throws Exception {
    // given a build that completes only once a second build runs beside it, as a build that waits
    // for the discovery timeout of an unreachable provider does
    final var bothInTheBuild = new CountDownLatch(2);
    final var decoder =
        new DeferredJwtDecoder(
            () -> {
              bothInTheBuild.countDown();
              awaitBoth(bothInTheBuild);
              return unused -> TOKEN;
            });

    // when two decodes run at the same time
    try (final var threads = Executors.newFixedThreadPool(2)) {
      final var first = threads.submit(() -> decoder.decode("token"));
      final var second = threads.submit(() -> decoder.decode("token"));

      // then neither decode waits for the build of the other, so a burst of requests for an
      // unreachable provider does not serialize into one timeout after another
      assertThat(first.get(5, TimeUnit.SECONDS)).isEqualTo(TOKEN);
      assertThat(second.get(5, TimeUnit.SECONDS)).isEqualTo(TOKEN);
    }
  }

  private static JwtDecoder decoderThatCounts(final AtomicInteger builds) {
    builds.incrementAndGet();
    return unused -> TOKEN;
  }

  private static void awaitBoth(final CountDownLatch latch) {
    try {
      assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
    } catch (final InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(interrupted);
    }
  }
}
