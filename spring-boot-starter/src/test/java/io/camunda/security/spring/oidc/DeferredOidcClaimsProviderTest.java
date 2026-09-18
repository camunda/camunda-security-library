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

import io.camunda.security.api.context.OidcClaimsProvider;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;

class DeferredOidcClaimsProviderTest {

  private static final Map<String, Object> JWT_CLAIMS =
      Map.of("iss", "https://idp.example", "scope", "openid", "sub", "alice");
  private static final Map<String, Object> AUGMENTED_CLAIMS =
      Map.of("sub", "alice", "groups", "admin");

  @Test
  void shouldKeepTheDelegateAfterASuccessfulBuild() {
    // given
    final var builds = new AtomicInteger();
    final var provider =
        new DeferredOidcClaimsProvider(
            "the mapping",
            () -> {
              builds.incrementAndGet();
              return augmentingProvider();
            });

    // when
    provider.claimsFor(JWT_CLAIMS, "token");
    provider.claimsFor(JWT_CLAIMS, "token");

    // then the mapping is built at the first lookup only, so discovery runs once
    assertThat(builds).hasValue(1);
  }

  @Test
  void shouldBuildTheDelegateAgainAfterAFailedBuild() {
    // given a provider that is unreachable for the first build
    final var builds = new AtomicInteger();
    final var provider =
        new DeferredOidcClaimsProvider(
            "the mapping",
            () -> {
              if (builds.incrementAndGet() == 1) {
                throw new IllegalStateException("unreachable");
              }
              return augmentingProvider();
            });
    assertThatThrownBy(() -> provider.claimsFor(JWT_CLAIMS, "token"))
        .isInstanceOf(AuthenticationServiceException.class);

    // when the provider answers again
    final var claims = provider.claimsFor(JWT_CLAIMS, "token");

    // then the deployment recovers without a restart
    assertThat(claims).isEqualTo(AUGMENTED_CLAIMS);
    assertThat(builds).hasValue(2);
  }

  @Test
  void shouldLetConcurrentLookupsBuildAtTheSameTime() throws Exception {
    // given a build that completes only once a second build runs beside it, as a build that waits
    // for the discovery timeout of an unreachable provider does
    final var bothInTheBuild = new CountDownLatch(2);
    final var provider =
        new DeferredOidcClaimsProvider(
            "the mapping",
            () -> {
              bothInTheBuild.countDown();
              awaitBoth(bothInTheBuild);
              return augmentingProvider();
            });

    // when two claims lookups run at the same time
    try (final var threads = Executors.newFixedThreadPool(2)) {
      final var first = threads.submit(() -> provider.claimsFor(JWT_CLAIMS, "token"));
      final var second = threads.submit(() -> provider.claimsFor(JWT_CLAIMS, "token"));

      // then neither lookup waits for the build of the other, so a burst of requests for an
      // unreachable provider does not serialize into one timeout after another
      assertThat(first.get(5, TimeUnit.SECONDS)).isEqualTo(AUGMENTED_CLAIMS);
      assertThat(second.get(5, TimeUnit.SECONDS)).isEqualTo(AUGMENTED_CLAIMS);
    }
  }

  @Test
  void shouldReportAFailedBuildAsAServerError() {
    // given a build that fails as OIDC discovery of an unreachable issuer fails
    final var unreachable = new IllegalArgumentException("Unable to resolve the Configuration");
    final var provider =
        new DeferredOidcClaimsProvider(
            "the mapping",
            () -> {
              throw unreachable;
            });

    // when
    // then the lookup does not answer with the classification of a refused credential, which the
    // token converter gives an IllegalArgumentException, because the token is not the reason
    assertThatThrownBy(() -> provider.claimsFor(JWT_CLAIMS, "token"))
        .isInstanceOf(AuthenticationServiceException.class)
        .hasCause(unreachable);
  }

  @Test
  void shouldPassAnUnaugmentableTokenWithoutBuildingTheDelegate() {
    // given a token that carries no openid scope, which no UserInfo endpoint can enrich
    final var builds = new AtomicInteger();
    final var provider =
        new DeferredOidcClaimsProvider(
            "the mapping",
            () -> {
              builds.incrementAndGet();
              throw new IllegalStateException("unreachable");
            });

    // when
    final var claims =
        provider.claimsFor(Map.of("iss", "https://idp.example", "sub", "alice"), "token");

    // then the request succeeds while the provider is unreachable, because it needs no augmentation
    assertThat(claims).isEqualTo(Map.of("iss", "https://idp.example", "sub", "alice"));
    assertThat(builds).hasValue(0);
  }

  private static OidcClaimsProvider augmentingProvider() {
    return (jwtClaims, tokenValue) -> AUGMENTED_CLAIMS;
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
