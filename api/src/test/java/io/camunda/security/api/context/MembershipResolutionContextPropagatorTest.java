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
}
