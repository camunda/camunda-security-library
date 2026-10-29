/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

class MembershipResolutionContextPropagatorTest {

  @Test
  void identityReturnsSupplierUnchanged() {
    // given
    final Supplier<List<String>> supplier = () -> List.of("a", "b");

    // when
    final var decorated = MembershipResolutionContextPropagator.identity().decorate(supplier);

    // then
    assertThat(decorated).isSameAs(supplier);
    assertThat(decorated.get()).containsExactly("a", "b");
  }

  @Test
  void decorateListBindsTheContextThroughDecorate() {
    // given a host propagator that binds a marker around the deferred lookup
    final var boundContext = new AtomicReference<String>();
    final MembershipResolutionContextPropagator propagator =
        supplier ->
            () -> {
              boundContext.set("bound");
              try {
                return supplier.get();
              } finally {
                boundContext.set(null);
              }
            };
    final var observedDuringLookup = new AtomicReference<String>();

    // when
    final Supplier<List<Integer>> decorated =
        propagator.decorateList(
            () -> {
              observedDuringLookup.set(boundContext.get());
              return List.of(1, 2);
            });

    // then
    assertThat(decorated.get()).containsExactly(1, 2);
    assertThat(observedDuringLookup.get()).isEqualTo("bound");
    assertThat(boundContext.get()).isNull();
  }

  @Test
  void decorateListCapturesTheContextWhenCalled() {
    // given a propagator that counts how often it decorates
    final var decorateCalls = new AtomicInteger();
    final MembershipResolutionContextPropagator propagator =
        supplier -> {
          decorateCalls.incrementAndGet();
          return supplier;
        };
    final var lookups = new AtomicInteger();

    // when
    propagator.decorateList(
        () -> {
          lookups.incrementAndGet();
          return List.of();
        });

    // then the context is captured now, but the lookup is still deferred
    assertThat(decorateCalls.get()).isEqualTo(1);
    assertThat(lookups.get()).isZero();
  }

  @Test
  void decorateListReturnsEachConcurrentCallItsOwnResult() throws Exception {
    // given a host propagator whose first call pauses after its lookup, so that a second call can
    // run in between
    final var firstLookupDone = new CountDownLatch(1);
    final var secondCallDone = new CountDownLatch(1);
    final var decoratedCalls = new AtomicInteger();
    final MembershipResolutionContextPropagator propagator =
        supplier ->
            () -> {
              final var lookedUp = supplier.get();
              if (decoratedCalls.incrementAndGet() == 1) {
                firstLookupDone.countDown();
                try {
                  // returns once the second call is done, or after a timeout if it's blocked
                  secondCallDone.await(500, TimeUnit.MILLISECONDS);
                } catch (final InterruptedException e) {
                  Thread.currentThread().interrupt();
                }
              }
              return lookedUp;
            };
    final var lookups = new AtomicInteger();
    final Supplier<List<Integer>> decorated =
        propagator.decorateList(() -> List.of(lookups.incrementAndGet()));

    // when two calls overlap
    final var first = CompletableFuture.supplyAsync(decorated::get);
    assertThat(firstLookupDone.await(5, TimeUnit.SECONDS)).isTrue();
    final var second =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return decorated.get();
              } finally {
                secondCallDone.countDown();
              }
            });

    // then each call gets the list from its own lookup
    assertThat(first.get(5, TimeUnit.SECONDS)).containsExactly(1);
    assertThat(second.get(5, TimeUnit.SECONDS)).containsExactly(2);
  }
}
