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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * The rate limit is keyed per subject and its state is static, so every test uses a unique subject
 * and therefore starts from "not warned yet".
 */
final class DeferredOidcResolutionTest {

  private final String subject = "subject-" + UUID.randomUUID();
  private final Logger logger = (Logger) LoggerFactory.getLogger(DeferredOidcResolution.class);
  private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
  private Level originalLevel;

  @BeforeEach
  void captureLogs() {
    originalLevel = logger.getLevel();
    logger.setLevel(Level.DEBUG);
    appender.start();
    logger.addAppender(appender);
  }

  @AfterEach
  void releaseLogs() {
    logger.detachAppender(appender);
    appender.stop();
    logger.setLevel(originalLevel);
  }

  @Test
  void shouldReturnTheResolvedValueWithoutLogging() {
    // when
    final var resolved = DeferredOidcResolution.resolve(subject, () -> "decoder");

    // then
    assertThat(resolved).isEqualTo("decoder");
    assertThat(appender.list).isEmpty();
  }

  @Test
  void shouldRethrowTheFailureUnchanged() {
    // given
    final var failure = new IllegalStateException("issuer unreachable");

    // when / then
    assertThatThrownBy(
            () ->
                DeferredOidcResolution.resolve(
                    subject,
                    () -> {
                      throw failure;
                    }))
        .isSameAs(failure);
  }

  @Test
  void shouldWarnOnceAndDebugTheRestWhileTheProviderStaysUnreachable() {
    // when the same subject fails repeatedly, as it does once per request during an outage
    for (int attempt = 0; attempt < 5; attempt++) {
      failOnce(subject);
    }

    // then the outage is reported, but a request-rate failure cannot fill the log with it
    assertThat(eventsAt(Level.WARN))
        .singleElement()
        .satisfies(
            event -> {
              assertThat(event.getFormattedMessage()).contains(subject);
              assertThat(event.getThrowableProxy()).isNotNull();
            });
    assertThat(eventsAt(Level.DEBUG)).hasSize(4);
  }

  @Test
  void shouldWarnPerSubject() {
    // given two subjects failing independently, as two providers in a multi-provider deployment do
    final var other = subject + "-other";

    // when
    failOnce(subject);
    failOnce(other);

    // then neither subject's outage is hidden by the other's rate limit
    assertThat(eventsAt(Level.WARN))
        .hasSize(2)
        .anySatisfy(event -> assertThat(event.getFormattedMessage()).contains(subject))
        .anySatisfy(event -> assertThat(event.getFormattedMessage()).contains(other));
  }

  @Test
  void shouldWarnOnceWhenConcurrentRequestsFailTogether() throws Exception {
    // given the request threads an outage hits at the same time
    final int threads = 8;
    final var ready = new CountDownLatch(threads);
    final var go = new CountDownLatch(1);
    final var failures = new AtomicInteger();

    // when
    try (final var executor = Executors.newFixedThreadPool(threads)) {
      for (int i = 0; i < threads; i++) {
        executor.execute(
            () -> {
              ready.countDown();
              try {
                go.await();
              } catch (final InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
              }
              failOnce(subject);
              failures.incrementAndGet();
            });
      }
      assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
      go.countDown();
    }

    // then the rate limit holds under concurrency
    assertThat(failures).hasValue(threads);
    assertThat(eventsAt(Level.WARN)).hasSize(1);
    assertThat(eventsAt(Level.DEBUG)).hasSize(threads - 1);
  }

  @Test
  void shouldKeepNoStateForASubjectThatStoppedFailing() {
    // given warnings for more subjects than one deployment fails on at a time, as a host that
    // creates and drops scopes produces over its lifetime
    for (int i = 0; i < 300; i++) {
      final var subject = "scope-" + UUID.randomUUID();
      assertThatThrownBy(
              () ->
                  DeferredOidcResolution.resolve(
                      subject,
                      () -> {
                        throw new IllegalStateException("unreachable");
                      }))
          .isInstanceOf(IllegalStateException.class);
    }

    // when the interval of each subject passes
    DeferredOidcResolution.removeIdleSubjects(System.nanoTime() + Duration.ofHours(1).toNanos());

    // then the rate limit holds state for the subjects that fail now only, so a long-running host
    // does not accumulate it
    assertThat(DeferredOidcResolution.trackedSubjectCount()).isZero();
  }

  @Test
  void shouldBoundTheRateLimitStateWhileManySubjectsFailAtTheSameTime() {
    // given failures for more subjects than the limit holds, inside one warning interval
    for (int i = 0; i < DeferredOidcResolution.MAX_TRACKED_SUBJECTS * 2; i++) {
      final var subject = "scope-" + UUID.randomUUID();
      assertThatThrownBy(
              () ->
                  DeferredOidcResolution.resolve(
                      subject,
                      () -> {
                        throw new IllegalStateException("unreachable");
                      }))
          .isInstanceOf(IllegalStateException.class);
    }

    // then the rate limit holds state for the limit at most, so no host grows it without a bound
    assertThat(DeferredOidcResolution.trackedSubjectCount())
        .isLessThanOrEqualTo(DeferredOidcResolution.MAX_TRACKED_SUBJECTS);
  }

  @Test
  void shouldBoundTheRateLimitStateWhileSubjectsFailInParallel() throws Exception {
    // given failures for more subjects than the limit holds, from several threads at a time
    try (final var threads = Executors.newFixedThreadPool(8)) {
      final var failures = new ArrayList<Future<?>>();
      for (int i = 0; i < DeferredOidcResolution.MAX_TRACKED_SUBJECTS * 4; i++) {
        final var subject = "scope-" + UUID.randomUUID();
        failures.add(
            threads.submit(
                () ->
                    assertThatThrownBy(
                            () ->
                                DeferredOidcResolution.resolve(
                                    subject,
                                    () -> {
                                      throw new IllegalStateException("unreachable");
                                    }))
                        .isInstanceOf(IllegalStateException.class)));
      }
      for (final var failure : failures) {
        failure.get(10, TimeUnit.SECONDS);
      }
    }

    // then the limit holds for parallel failures as well, so no burst of new scopes passes it
    assertThat(DeferredOidcResolution.trackedSubjectCount())
        .isLessThanOrEqualTo(DeferredOidcResolution.MAX_TRACKED_SUBJECTS);
  }

  @Test
  void shouldNameTheProviderAndItsIssuerInTheSubject() {
    // given
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put(
        "discovered",
        OidcConfiguration.builder()
            .clientId("client")
            .issuerUri("https://idp.example.com/realms/camunda")
            .build());
    providers.put(
        "explicit",
        OidcConfiguration.builder()
            .clientId("client")
            .authorizationUri("https://idp.example.com/auth")
            .tokenUri("https://idp.example.com/token")
            .jwkSetUri("https://idp.example.com/jwks")
            .build());

    // when / then an operator can tell which provider and endpoint a failure is about; a provider
    // configured with explicit endpoints has no issuer to name
    assertThat(DeferredOidcResolution.describeProviders(providers))
        .isEqualTo("'discovered' (issuer https://idp.example.com/realms/camunda), 'explicit'");
  }

  private void failOnce(final String logSubject) {
    try {
      DeferredOidcResolution.resolve(
          logSubject,
          () -> {
            throw new IllegalStateException("issuer unreachable");
          });
    } catch (final IllegalStateException expected) {
      // the caller's failure, rethrown unchanged — asserted separately
    }
  }

  private List<ILoggingEvent> eventsAt(final Level level) {
    return appender.list.stream().filter(event -> event.getLevel() == level).toList();
  }
}
